use ratatui::layout::Rect;

use crate::settings::{TerminalLayout, TerminalSizes};

const MIN_PANE_WIDTH: usize = 12;
const MIN_PANE_HEIGHT: usize = 4;

#[derive(Default)]
pub struct PaneLayout {
    area: Rect,
    layout: TerminalLayout,
    start: usize,
    len: usize,
    columns: Vec<u16>,
    rows: Vec<u16>,
}

#[derive(Clone, Copy, Debug)]
pub struct PaneDivider {
    pub area: Rect,
    pub vertical: bool,
    bounds: Rect,
    layout: TerminalLayout,
    parts: usize,
    index: usize,
    position: u16,
    minimum: u16,
    maximum: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct PaneResize {
    divider: PaneDivider,
    pointer: u16,
    position: u16,
}

impl PaneDivider {
    pub fn start(self, column: u16, row: u16) -> PaneResize {
        PaneResize {
            divider: self,
            pointer: if self.vertical { column } else { row },
            position: self.position,
        }
    }
}

impl PaneResize {
    pub fn update(&mut self, column: u16, row: u16) {
        let pointer = if self.divider.vertical { column } else { row };
        let delta = i32::from(pointer) - i32::from(self.pointer);
        self.position = (i32::from(self.divider.position) + delta)
            .clamp(i32::from(self.divider.minimum), i32::from(self.divider.maximum)) as u16;
    }
}

impl PaneLayout {
    pub fn arrange(
        &mut self,
        area: Rect,
        layout: TerminalLayout,
        count: usize,
        active: usize,
        sizes: &TerminalSizes,
        preview: Option<PaneResize>,
    ) {
        self.area = area;
        self.layout = layout;
        self.start = 0;
        self.len = 0;
        let (columns, rows) = if count == 0 || area.width == 0 || area.height == 0 {
            (1, 1)
        } else {
            let max_columns = (usize::from(area.width) / MIN_PANE_WIDTH).max(1);
            let max_rows = (usize::from(area.height) / MIN_PANE_HEIGHT).max(1);
            let capacity = match layout {
                TerminalLayout::Single => 1,
                TerminalLayout::SideBySide => max_columns,
                TerminalLayout::Stacked => max_rows,
                TerminalLayout::Grid => max_columns * max_rows,
            };
            self.start = active.min(count - 1) / capacity * capacity;
            self.len = (count - self.start).min(capacity);
            match layout {
                TerminalLayout::Single => (1, 1),
                TerminalLayout::SideBySide => (self.len, 1),
                TerminalLayout::Stacked => (1, self.len),
                TerminalLayout::Grid => grid_dimensions(self.len, max_columns, max_rows),
            }
        };
        let (widths, heights) = match layout {
            TerminalLayout::Single => (&[][..], &[][..]),
            TerminalLayout::SideBySide => (sizes.side_by_side.as_slice(), &[][..]),
            TerminalLayout::Stacked => (&[][..], sizes.stacked.as_slice()),
            TerminalLayout::Grid => (sizes.grid_columns.as_slice(), sizes.grid_rows.as_slice()),
        };
        fill_axis(&mut self.columns, area.x, area.width, columns, MIN_PANE_WIDTH, widths);
        fill_axis(&mut self.rows, area.y, area.height, rows, MIN_PANE_HEIGHT, heights);
        if let Some(preview) = preview.filter(|preview| self.matches(preview.divider)) {
            let (axis, minimum) = if preview.divider.vertical {
                (&mut self.columns, MIN_PANE_WIDTH as u16)
            } else {
                (&mut self.rows, MIN_PANE_HEIGHT as u16)
            };
            let index = preview.divider.index;
            axis[index] = preview.position.clamp(axis[index - 1] + minimum, axis[index + 1] - minimum);
        }
    }

    pub fn panes(&self) -> impl Iterator<Item = (usize, Rect)> + '_ {
        let columns = self.columns.len().saturating_sub(1).max(1);
        (0..self.len).map(move |slot| {
            let column = slot % columns;
            let row = slot / columns;
            (self.start + slot, Rect::new(
                self.columns[column],
                self.rows[row],
                self.columns[column + 1] - self.columns[column],
                self.rows[row + 1] - self.rows[row],
            ))
        })
    }

    pub fn dividers(&self) -> impl Iterator<Item = PaneDivider> + '_ {
        let columns = self.columns.len().saturating_sub(1);
        let rows = self.rows.len().saturating_sub(1);
        let vertical = (0..rows).flat_map(move |row| {
            (1..columns).filter_map(move |index| {
                if row * columns + index - 1 >= self.len {
                    return None;
                }
                let area = Rect::new(
                    self.columns[index] - 1,
                    self.rows[row] + 1,
                    1,
                    (self.rows[row + 1] - self.rows[row]).saturating_sub(2),
                );
                (area.height > 0).then(|| self.divider(true, index, area))
            })
        });
        let horizontal = (1..rows).flat_map(move |index| {
            (0..columns).filter_map(move |column| {
                if (index - 1) * columns + column >= self.len {
                    return None;
                }
                let area = Rect::new(
                    self.columns[column] + 1,
                    self.rows[index] - 1,
                    (self.columns[column + 1] - self.columns[column]).saturating_sub(2),
                    1,
                );
                (area.width > 0).then(|| self.divider(false, index, area))
            })
        });
        vertical.chain(horizontal)
    }

    fn divider(&self, vertical: bool, index: usize, area: Rect) -> PaneDivider {
        let (axis, minimum) = if vertical {
            (&self.columns, MIN_PANE_WIDTH as u16)
        } else {
            (&self.rows, MIN_PANE_HEIGHT as u16)
        };
        PaneDivider {
            area,
            vertical,
            bounds: self.area,
            layout: self.layout,
            parts: axis.len() - 1,
            index,
            position: axis[index],
            minimum: axis[index - 1] + minimum,
            maximum: axis[index + 1] - minimum,
        }
    }

    fn matches(&self, divider: PaneDivider) -> bool {
        let axis = if divider.vertical { &self.columns } else { &self.rows };
        self.len > 0 && self.area == divider.bounds && self.layout == divider.layout
            && axis.len() == divider.parts + 1
            && divider.index > 0 && divider.index < divider.parts
    }

    pub fn resized(&self, resize: PaneResize, sizes: &TerminalSizes) -> Option<TerminalSizes> {
        let divider = resize.divider;
        if !self.matches(divider) || resize.position == divider.position {
            return None;
        }
        let mut candidate = sizes.clone();
        let target = match (self.layout, divider.vertical) {
            (TerminalLayout::SideBySide, true) => &mut candidate.side_by_side,
            (TerminalLayout::Stacked, false) => &mut candidate.stacked,
            (TerminalLayout::Grid, true) => &mut candidate.grid_columns,
            (TerminalLayout::Grid, false) => &mut candidate.grid_rows,
            _ => return None,
        };
        let (axis, origin, size) = if divider.vertical {
            (&self.columns, self.area.x, self.area.width)
        } else {
            (&self.rows, self.area.y, self.area.height)
        };
        target.clear();
        target.extend((1..divider.parts).map(|index| {
            let position = if index == divider.index { resize.position } else { axis[index] };
            ((u32::from(position - origin) * u32::from(u16::MAX) + u32::from(size) / 2)
                / u32::from(size)) as u16
        }));
        Some(candidate)
    }
}

fn grid_dimensions(count: usize, max_columns: usize, max_rows: usize) -> (usize, usize) {
    let floor = count.isqrt();
    let mut columns = floor + usize::from(floor * floor != count);
    columns = columns.min(max_columns);

    let mut rows = count.div_ceil(columns);
    if rows > max_rows {
        rows = max_rows;
        columns = count.div_ceil(rows);
    }
    (columns, rows)
}

fn fill_axis(axis: &mut Vec<u16>, origin: u16, size: u16, parts: usize, minimum: usize, splits: &[u16]) {
    axis.clear();
    axis.push(origin);
    let size = usize::from(size);
    let minimum = minimum.min(size / parts);
    for index in 1..parts {
        let offset = if splits.len() == parts - 1 {
            (usize::from(splits[index - 1]) * size + usize::from(u16::MAX) / 2) / usize::from(u16::MAX)
        } else {
            index * (size / parts) + index.min(size % parts)
        };
        let lower = usize::from(axis[index - 1] - origin) + minimum;
        let upper = size - minimum * (parts - index);
        axis.push(origin.saturating_add(offset.clamp(lower, upper) as u16));
    }
    axis.push(origin.saturating_add(size as u16));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panes(area: Rect, layout: TerminalLayout, count: usize, active: usize) -> std::vec::IntoIter<(usize, Rect)> {
        let mut geometry = PaneLayout::default();
        geometry.arrange(area, layout, count, active, &TerminalSizes::default(), None);
        geometry.panes().collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn preview_can_be_cancelled_or_committed_without_moving_unrelated_columns() {
        let area = Rect::new(7, 9, 101, 30);
        let mut geometry = PaneLayout::default();
        let sizes = TerminalSizes::default();
        geometry.arrange(area, TerminalLayout::SideBySide, 3, 0, &sizes, None);
        let original = geometry.panes().collect::<Vec<_>>();
        let divider = geometry.dividers().next().unwrap();
        let mut resize = divider.start(divider.area.x, divider.area.y);
        assert!(geometry.resized(resize, &sizes).is_none());
        resize.update(divider.area.x + 10, divider.area.y);
        geometry.arrange(area, TerminalLayout::SideBySide, 3, 0, &sizes, Some(resize));
        let preview = geometry.panes().collect::<Vec<_>>();
        assert_eq!(preview, vec![
            (0, Rect::new(7, 9, 44, 30)),
            (1, Rect::new(51, 9, 24, 30)),
            (2, original[2].1),
        ]);
        geometry.arrange(area, TerminalLayout::SideBySide, 3, 0, &sizes, None);
        assert_eq!(geometry.panes().collect::<Vec<_>>(), original);
        let saved = geometry.resized(resize, &sizes).unwrap();
        geometry.arrange(area, TerminalLayout::SideBySide, 3, 2, &saved, None);
        assert_eq!(geometry.panes().collect::<Vec<_>>(), preview);
    }

    #[test]
    fn dragging_past_neighbours_clamps_both_axes_without_collapsing_panes() {
        let sizes = TerminalSizes::default();
        let mut geometry = PaneLayout::default();
        let area = Rect::new(7, 9, 101, 30);
        geometry.arrange(area, TerminalLayout::SideBySide, 3, 0, &sizes, None);
        let divider = geometry.dividers().next().unwrap();
        let mut resize = divider.start(divider.area.x, divider.area.y);
        resize.update(0, 0);
        geometry.arrange(area, TerminalLayout::SideBySide, 3, 0, &sizes, Some(resize));
        assert_eq!(geometry.panes().map(|(_, pane)| pane.width).collect::<Vec<_>>(), [12, 56, 33]);
        resize.update(u16::MAX, 0);
        geometry.arrange(area, TerminalLayout::SideBySide, 3, 0, &sizes, Some(resize));
        assert_eq!(geometry.panes().map(|(_, pane)| pane.width).collect::<Vec<_>>(), [56, 12, 33]);

        let area = Rect::new(3, 4, 70, 43);
        geometry.arrange(area, TerminalLayout::Stacked, 4, 0, &sizes, None);
        let divider = geometry.dividers().find(|divider| divider.index == 2).unwrap();
        let mut resize = divider.start(divider.area.x, divider.area.y);
        resize.update(0, u16::MAX);
        geometry.arrange(area, TerminalLayout::Stacked, 4, 0, &sizes, Some(resize));
        assert_eq!(geometry.panes().map(|(_, pane)| pane.height).collect::<Vec<_>>(), [11, 18, 4, 10]);
        resize.update(0, 0);
        geometry.arrange(area, TerminalLayout::Stacked, 4, 0, &sizes, Some(resize));
        assert_eq!(geometry.panes().map(|(_, pane)| pane.height).collect::<Vec<_>>(), [11, 4, 18, 10]);
    }

    #[test]
    fn grid_proportions_survive_viewport_and_layout_changes() {
        let mut sizes = TerminalSizes::default();
        let mut geometry = PaneLayout::default();
        let area = Rect::new(4, 6, 100, 40);
        geometry.arrange(area, TerminalLayout::Grid, 4, 0, &sizes, None);
        let divider = geometry.dividers().find(|divider| divider.vertical).unwrap();
        let mut resize = divider.start(divider.area.x, divider.area.y);
        resize.update(divider.area.x + 10, divider.area.y);
        sizes = geometry.resized(resize, &sizes).unwrap();
        geometry.arrange(area, TerminalLayout::Grid, 4, 0, &sizes, None);
        let divider = geometry.dividers().find(|divider| !divider.vertical).unwrap();
        let mut resize = divider.start(divider.area.x, divider.area.y);
        resize.update(divider.area.x, divider.area.y - 6);
        sizes = geometry.resized(resize, &sizes).unwrap();

        geometry.arrange(Rect::new(4, 6, 200, 80), TerminalLayout::Grid, 4, 3, &sizes, None);
        assert_eq!(geometry.panes().map(|(_, pane)| (pane.width, pane.height)).collect::<Vec<_>>(),
            [(120, 28), (80, 28), (120, 52), (80, 52)]);
        geometry.arrange(Rect::new(4, 6, 24, 8), TerminalLayout::Grid, 4, 1, &sizes, None);
        assert_eq!(geometry.panes().map(|(_, pane)| (pane.width, pane.height)).collect::<Vec<_>>(),
            [(12, 4); 4]);
        geometry.arrange(area, TerminalLayout::SideBySide, 4, 0, &sizes, None);
        assert_eq!(geometry.panes().map(|(_, pane)| pane.width).collect::<Vec<_>>(), [25; 4]);
        for active in 0..4 {
            geometry.arrange(area, TerminalLayout::Grid, 4, active, &sizes, None);
            assert_eq!(geometry.panes().map(|(_, pane)| (pane.width, pane.height)).collect::<Vec<_>>(),
                [(60, 14), (40, 14), (60, 26), (40, 26)]);
        }
    }

    #[test]
    fn stale_drags_are_rejected_after_geometry_changes() {
        let mut geometry = PaneLayout::default();
        let sizes = TerminalSizes::default();
        let area = Rect::new(0, 0, 120, 40);
        geometry.arrange(area, TerminalLayout::Grid, 4, 0, &sizes, None);
        let divider = geometry.dividers().next().unwrap();
        let mut resize = divider.start(divider.area.x, divider.area.y);
        resize.update(divider.area.x + 10, divider.area.y);
        for (area, layout, count) in [
            (Rect::new(0, 0, 119, 40), TerminalLayout::Grid, 4),
            (area, TerminalLayout::Stacked, 4),
            (area, TerminalLayout::Grid, 9),
            (area, TerminalLayout::Grid, 0),
        ] {
            geometry.arrange(area, layout, count, 0, &sizes, Some(resize));
            assert!(geometry.resized(resize, &sizes).is_none());
            assert_eq!(geometry.panes().collect::<Vec<_>>(), panes(area, layout, count, 0).collect::<Vec<_>>());
        }
    }

    #[test]
    fn dividers_stay_on_borders_and_do_not_cover_terminal_contents_or_titles() {
        let mut geometry = PaneLayout::default();
        let sizes = TerminalSizes::default();
        let area = Rect::new(3, 5, 101, 41);
        for layout in [TerminalLayout::SideBySide, TerminalLayout::Stacked, TerminalLayout::Grid] {
            geometry.arrange(area, layout, 5, 0, &sizes, None);
            for divider in geometry.dividers() {
                assert!(divider.area.x >= area.x && divider.area.right() <= area.right());
                assert!(divider.area.y >= area.y && divider.area.bottom() <= area.bottom());
                for (_, pane) in geometry.panes() {
                    let content_and_title = Rect::new(pane.x + 1, pane.y, pane.width - 2, pane.height - 1);
                    assert!(!divider.area.intersects(content_and_title));
                }
            }
        }
        for (area, layout) in [
            (Rect::new(0, 0, 24, 1), TerminalLayout::SideBySide),
            (Rect::new(0, 0, 1, 8), TerminalLayout::Stacked),
            (Rect::new(0, 0, 0, 0), TerminalLayout::Grid),
        ] {
            geometry.arrange(area, layout, 4, 0, &sizes, None);
            assert_eq!(geometry.dividers().count(), 0);
        }
    }

    #[test]
    fn four_session_grid_is_two_by_two() {
        let area = Rect::new(5, 7, 25, 9);
        let actual = panes(area, TerminalLayout::Grid, 4, 0).collect::<Vec<_>>();

        assert_eq!(
            actual,
            vec![
                (0, Rect::new(5, 7, 13, 5)),
                (1, Rect::new(18, 7, 12, 5)),
                (2, Rect::new(5, 12, 13, 4)),
                (3, Rect::new(18, 12, 12, 4)),
            ]
        );
    }

    #[test]
    fn columns_and_rows_distribute_odd_cells_in_order() {
        let area = Rect::new(3, 2, 37, 13);
        let columns = panes(area, TerminalLayout::SideBySide, 3, 1).collect::<Vec<_>>();
        assert_eq!(
            columns,
            vec![
                (0, Rect::new(3, 2, 13, 13)),
                (1, Rect::new(16, 2, 12, 13)),
                (2, Rect::new(28, 2, 12, 13)),
            ]
        );

        let rows = panes(area, TerminalLayout::Stacked, 3, 1).collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![
                (0, Rect::new(3, 2, 37, 5)),
                (1, Rect::new(3, 7, 37, 4)),
                (2, Rect::new(3, 11, 37, 4)),
            ]
        );
    }

    #[test]
    fn odd_grid_cells_do_not_overlap_or_escape_the_area() {
        let area = Rect::new(4, 6, 37, 13);
        let actual = panes(area, TerminalLayout::Grid, 7, 4).collect::<Vec<_>>();

        assert_eq!(
            actual.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            (0..7).collect::<Vec<_>>()
        );
        for (position, (_, pane)) in actual.iter().enumerate() {
            assert!(pane.x >= area.x && pane.y >= area.y);
            assert!(pane.right() <= area.right() && pane.bottom() <= area.bottom());
            for (_, other) in &actual[position + 1..] {
                let overlaps = pane.x < other.right()
                    && pane.right() > other.x
                    && pane.y < other.bottom()
                    && pane.bottom() > other.y;
                assert!(!overlaps);
            }
        }
    }

    #[test]
    fn paging_is_bounded_and_keeps_the_active_session_visible() {
        let area = Rect::new(0, 0, 24, 8);
        let middle = panes(area, TerminalLayout::SideBySide, 5, 3).collect::<Vec<_>>();
        assert!(middle.iter().any(|(index, _)| *index == 3));
        assert!(middle.len() <= 2);

        let beyond_end = panes(area, TerminalLayout::SideBySide, 5, usize::MAX)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert!(beyond_end.contains(&4));
        assert!(beyond_end.len() <= 2);
        assert!(beyond_end.iter().all(|index| *index < 5));
    }

    #[test]
    fn focusing_a_visible_pane_keeps_the_current_page_in_place() {
        let area = Rect::new(0, 0, 24, 8);
        for layout in [TerminalLayout::SideBySide, TerminalLayout::Stacked, TerminalLayout::Grid] {
            let page = panes(area, layout, 8, 7).collect::<Vec<_>>();
            for (active, _) in &page {
                assert_eq!(panes(area, layout, 8, *active).collect::<Vec<_>>(), page);
            }
        }
    }

    #[test]
    fn tiny_and_empty_areas_are_safe() {
        let tiny = Rect::new(9, 11, 1, 1);
        assert_eq!(
            panes(tiny, TerminalLayout::Grid, 4, 2).collect::<Vec<_>>(),
            vec![(2, tiny)]
        );
        assert_eq!(panes(tiny, TerminalLayout::Single, 2, 99).collect::<Vec<_>>(), vec![(1, tiny)]);
        assert_eq!(panes(Rect::new(0, 0, 0, 4), TerminalLayout::Grid, 2, 0).count(), 0);
        assert_eq!(panes(Rect::new(0, 0, 4, 0), TerminalLayout::Grid, 2, 0).count(), 0);
        assert_eq!(panes(tiny, TerminalLayout::Grid, 0, 0).count(), 0);
    }

    #[test]
    fn sessions_return_when_the_grid_viewport_grows() {
        let constrained = panes(Rect::new(0, 0, 24, 4), TerminalLayout::Grid, 6, 4)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert!(constrained.contains(&4));
        assert!(constrained.len() <= 2);

        let expanded = panes(Rect::new(0, 0, 36, 8), TerminalLayout::Grid, 6, 4)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(expanded, (0..6).collect::<Vec<_>>());
    }
}

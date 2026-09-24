use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::vault::{Auth, Category, Credential, Host, Vault};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Section {
    Sessions,
    Servers,
    Credentials,
    Tools,
    Sync,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RowKey {
    Section(Section),
    Session(Uuid),
    Category(Uuid),
    Host(Uuid),
    Ungrouped,
    Credential(Uuid),
    Snippets,
    Snippet(Uuid),
    Sync,
}

#[derive(Clone, Debug)]
pub struct CatalogRow {
    pub key: RowKey,
    pub label: String,
    pub indent: u16,
    pub expandable: bool,
    pub expanded: bool,
}

#[derive(Clone, Copy)]
pub struct SessionEntry<'a> {
    pub id: Uuid,
    pub label: &'a str,
}

pub struct Catalog {
    rows: Vec<CatalogRow>,
    selected: usize,
    viewport: usize,
    filter: String,
    expanded_categories: HashSet<Uuid>,
    expanded_sections: HashSet<Section>,
    ungrouped_expanded: bool,
    needs_rebuild: bool,
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            selected: 0,
            viewport: 0,
            filter: String::new(),
            expanded_categories: HashSet::new(),
            expanded_sections: HashSet::from([
                Section::Sessions,
                Section::Servers,
                Section::Credentials,
                Section::Tools,
                Section::Sync,
            ]),
            ungrouped_expanded: true,
            needs_rebuild: true,
        }
    }
}

impl Catalog {
    pub fn rows(&self) -> &[CatalogRow] {
        &self.rows
    }

    pub fn selected_index(&self) -> usize {
        self.selected
    }

    pub fn selected(&self) -> Option<&CatalogRow> {
        self.rows.get(self.selected)
    }

    pub fn selected_key(&self) -> Option<RowKey> {
        self.selected().map(|row| row.key.clone())
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn set_filter(&mut self, filter: String) {
        let normalized = filter.trim().to_owned();
        if self.filter != normalized {
            self.filter = normalized;
            self.needs_rebuild = true;
        }
    }

    pub fn invalidate(&mut self) {
        self.needs_rebuild = true;
    }

    pub fn rebuild<'a>(
        &mut self,
        vault: &Vault,
        sessions: impl ExactSizeIterator<Item = SessionEntry<'a>>,
    ) {
        if !self.needs_rebuild {
            return;
        }
        let sessions_empty = sessions.len() == 0;
        let old_key = self.selected_key();
        // A moved record remains selected even if its new parent was collapsed.
        let mut parent = match old_key.as_ref() {
            Some(RowKey::Host(id)) => {
                self.expanded_sections.insert(Section::Servers);
                let category = vault
                    .hosts
                    .iter()
                    .find(|host| host.id == *id)
                    .and_then(|host| host.category_id);
                if category.is_none() {
                    self.ungrouped_expanded = true;
                }
                category
            }
            Some(RowKey::Category(id)) => {
                self.expanded_sections.insert(Section::Servers);
                vault
                    .categories
                    .iter()
                    .find(|category| category.id == *id)
                    .and_then(|category| category.parent_id)
            }
            _ => None,
        };
        while let Some(id) = parent {
            self.expanded_categories.insert(id);
            parent = vault
                .categories
                .iter()
                .find(|category| category.id == id)
                .and_then(|category| category.parent_id);
        }
        let first_build = old_key.is_none() && self.rows.is_empty();
        let old_index = self.selected;
        let query = self.filter.to_lowercase();
        let filtering = !query.is_empty();
        let mut rows = Vec::new();

        self.push_section(&mut rows, Section::Sessions, "Sessions");
        if self.section_open(Section::Sessions, filtering) {
            for session in sessions {
                if query.is_empty() || session.label.to_lowercase().contains(&query) {
                    rows.push(CatalogRow {
                        key: RowKey::Session(session.id),
                        label: session.label.to_owned(),
                        indent: 1,
                        expandable: false,
                        expanded: false,
                    });
                }
            }
        }

        self.push_section(&mut rows, Section::Servers, "Servers");
        if self.section_open(Section::Servers, filtering) {
            let credentials: HashMap<_, _> = vault
                .credentials
                .iter()
                .map(|credential| (credential.id, credential))
                .collect();
            let mut children: HashMap<Option<Uuid>, Vec<&Category>> = HashMap::new();
            for category in &vault.categories {
                children
                    .entry(category.parent_id)
                    .or_default()
                    .push(category);
            }
            for entries in children.values_mut() {
                entries.sort_by_cached_key(|entry| (entry.label.to_lowercase(), entry.id));
            }
            let mut hosts: HashMap<Option<Uuid>, Vec<&Host>> = HashMap::new();
            for host in &vault.hosts {
                hosts.entry(host.category_id).or_default().push(host);
            }
            for entries in hosts.values_mut() {
                entries.sort_by_cached_key(|entry| (entry.label.to_lowercase(), entry.id));
            }
            let paths = if filtering {
                category_paths(&vault.categories)
            } else {
                HashMap::new()
            };
            let search = Search {
                query: &query,
                children: &children,
                hosts: &hosts,
                credentials: &credentials,
                paths: &paths,
            };
            if let Some(roots) = children.get(&None) {
                for category in roots {
                    self.push_category(&mut rows, category, 1, filtering, &search);
                }
            }
            let ungrouped_matches = hosts
                .get(&None)
                .is_some_and(|entries| entries.iter().any(|host| search.host_matches(host)));
            if !filtering || ungrouped_matches {
                rows.push(CatalogRow {
                    key: RowKey::Ungrouped,
                    label: "Ungrouped".to_owned(),
                    indent: 1,
                    expandable: true,
                    expanded: self.ungrouped_expanded,
                });
                if self.ungrouped_expanded || filtering {
                    if let Some(entries) = hosts.get(&None) {
                        for host in entries {
                            if search.host_matches(host) {
                                rows.push(CatalogRow {
                                    key: RowKey::Host(host.id),
                                    label: host.label.clone(),
                                    indent: 2,
                                    expandable: false,
                                    expanded: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        self.push_section(&mut rows, Section::Credentials, "Credentials");
        if self.section_open(Section::Credentials, filtering) {
            let mut credentials: Vec<_> = vault.credentials.iter().collect();
            credentials.sort_by_cached_key(|entry| (entry.label.to_lowercase(), entry.id));
            for credential in credentials {
                if credential_matches(credential, &query) {
                    rows.push(CatalogRow {
                        key: RowKey::Credential(credential.id),
                        label: if matches!(&credential.auth, Auth::Agent) {
                            format!("{} · local agent required", credential.label)
                        } else {
                            credential.label.clone()
                        },
                        indent: 1,
                        expandable: false,
                        expanded: false,
                    });
                }
            }
        }

        self.push_section(&mut rows, Section::Tools, "Tools");
        if self.section_open(Section::Tools, filtering) {
            let mut snippets: Vec<_> = vault.snippets.iter().collect();
            snippets.sort_by_cached_key(|entry| (entry.label.to_lowercase(), entry.id));
            let matching: Vec<_> = snippets
                .into_iter()
                .filter(|snippet| {
                    query.is_empty()
                        || snippet.label.to_lowercase().contains(&query)
                        || snippet.command.to_lowercase().contains(&query)
                })
                .collect();
            if !filtering || !matching.is_empty() || "snippets".contains(&query) {
                rows.push(CatalogRow {
                    key: RowKey::Snippets,
                    label: "Snippets".to_owned(),
                    indent: 1,
                    expandable: false,
                    expanded: false,
                });
                for snippet in matching {
                    rows.push(CatalogRow {
                        key: RowKey::Snippet(snippet.id),
                        label: snippet.label.clone(),
                        indent: 2,
                        expandable: false,
                        expanded: false,
                    });
                }
            }
        }

        self.push_section(&mut rows, Section::Sync, "Sync");
        if self.section_open(Section::Sync, filtering)
            && (query.is_empty() || "sync".contains(&query))
        {
            rows.push(CatalogRow {
                key: RowKey::Sync,
                label: "Settings and status".to_owned(),
                indent: 1,
                expandable: false,
                expanded: false,
            });
        }

        self.rows = rows;
        self.selected = old_key
            .and_then(|key| self.rows.iter().position(|row| row.key == key))
            .unwrap_or_else(|| {
                old_index
                    .saturating_sub(1)
                    .min(self.rows.len().saturating_sub(1))
            });
        if first_build
            && sessions_empty
            && vault.categories.is_empty()
            && vault.credentials.is_empty()
            && vault.hosts.is_empty()
            && vault.snippets.is_empty()
        {
            if let Some(index) = self
                .rows
                .iter()
                .position(|row| row.key == RowKey::Section(Section::Credentials))
            {
                self.selected = index;
            }
        }
        if self.rows.is_empty() {
            self.selected = 0;
            self.viewport = 0;
        }
        self.needs_rebuild = false;
    }

    fn push_section(&self, rows: &mut Vec<CatalogRow>, section: Section, label: &str) {
        rows.push(CatalogRow {
            key: RowKey::Section(section),
            label: label.to_owned(),
            indent: 0,
            expandable: true,
            expanded: self.expanded_sections.contains(&section),
        });
    }

    fn section_open(&self, section: Section, filtering: bool) -> bool {
        filtering || self.expanded_sections.contains(&section)
    }

    fn push_category(
        &self,
        rows: &mut Vec<CatalogRow>,
        category: &Category,
        indent: u16,
        filtering: bool,
        search: &Search<'_>,
    ) {
        if !search.category_has_match(category.id) {
            return;
        }
        let expanded = self.expanded_categories.contains(&category.id);
        rows.push(CatalogRow {
            key: RowKey::Category(category.id),
            label: category.label.clone(),
            indent,
            expandable: true,
            expanded: expanded || filtering,
        });
        if !expanded && !filtering {
            return;
        }
        if let Some(children) = search.children.get(&Some(category.id)) {
            for child in children {
                self.push_category(rows, child, indent.saturating_add(1), filtering, search);
            }
        }
        if let Some(hosts) = search.hosts.get(&Some(category.id)) {
            for host in hosts {
                if search.host_matches(host) {
                    rows.push(CatalogRow {
                        key: RowKey::Host(host.id),
                        label: host.label.clone(),
                        indent: indent.saturating_add(1),
                        expandable: false,
                        expanded: false,
                    });
                }
            }
        }
    }

    pub fn move_selection(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        self.selected = if delta < 0 {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            self.selected
                .saturating_add(delta as usize)
                .min(self.rows.len() - 1)
        };
    }

    pub fn select(&mut self, key: &RowKey) -> bool {
        if let Some(index) = self.rows.iter().position(|row| &row.key == key) {
            self.selected = index;
            true
        } else {
            false
        }
    }

    pub fn expand_selected(&mut self) {
        let Some(key) = self.selected_key() else {
            return;
        };
        match key {
            RowKey::Section(section) => {
                self.expanded_sections.insert(section);
                self.needs_rebuild = true;
            }
            RowKey::Category(id) => {
                self.expanded_categories.insert(id);
                self.needs_rebuild = true;
            }
            RowKey::Ungrouped => {
                self.ungrouped_expanded = true;
                self.needs_rebuild = true;
            }
            _ => {}
        }
    }

    pub fn collapse_selected(&mut self, vault: &Vault) {
        let Some(key) = self.selected_key() else {
            return;
        };
        match key {
            RowKey::Section(section) => {
                self.expanded_sections.remove(&section);
                self.needs_rebuild = true;
            }
            RowKey::Category(id) if self.expanded_categories.remove(&id) => {
                self.needs_rebuild = true;
            }
            RowKey::Category(id) => {
                if let Some(parent) = vault
                    .categories
                    .iter()
                    .find(|category| category.id == id)
                    .and_then(|category| category.parent_id)
                {
                    self.select(&RowKey::Category(parent));
                }
            }
            RowKey::Ungrouped => {
                self.ungrouped_expanded = false;
                self.needs_rebuild = true;
            }
            _ => {}
        }
    }

    pub fn toggle_selected(&mut self) {
        let Some(row) = self.selected().cloned() else {
            return;
        };
        if row.expanded {
            match row.key {
                RowKey::Section(section) => {
                    self.expanded_sections.remove(&section);
                }
                RowKey::Category(id) => {
                    self.expanded_categories.remove(&id);
                }
                RowKey::Ungrouped => self.ungrouped_expanded = false,
                _ => return,
            }
        } else {
            match row.key {
                RowKey::Section(section) => {
                    self.expanded_sections.insert(section);
                }
                RowKey::Category(id) => {
                    self.expanded_categories.insert(id);
                }
                RowKey::Ungrouped => self.ungrouped_expanded = true,
                _ => return,
            }
        }
        self.needs_rebuild = true;
    }

    pub fn visible_range(&mut self, height: usize) -> std::ops::Range<usize> {
        if self.rows.is_empty() || height == 0 {
            self.viewport = 0;
            return 0..0;
        }
        if self.selected < self.viewport {
            self.viewport = self.selected;
        } else if self.selected >= self.viewport.saturating_add(height) {
            self.viewport = self.selected + 1 - height;
        }
        let maximum = self.rows.len().saturating_sub(height);
        self.viewport = self.viewport.min(maximum);
        self.viewport..(self.viewport + height).min(self.rows.len())
    }
}

struct Search<'a> {
    query: &'a str,
    children: &'a HashMap<Option<Uuid>, Vec<&'a Category>>,
    hosts: &'a HashMap<Option<Uuid>, Vec<&'a Host>>,
    credentials: &'a HashMap<Uuid, &'a Credential>,
    paths: &'a HashMap<Uuid, String>,
}

impl Search<'_> {
    fn host_matches(&self, host: &Host) -> bool {
        if self.query.is_empty() {
            return true;
        }
        host.label.to_lowercase().contains(self.query)
            || host.hostname.to_lowercase().contains(self.query)
            || self
                .credentials
                .get(&host.credential_id)
                .is_some_and(|credential| {
                    credential.label.to_lowercase().contains(self.query)
                        || credential.username.to_lowercase().contains(self.query)
                })
            || host
                .category_id
                .and_then(|id| self.paths.get(&id))
                .is_some_and(|path| path.contains(self.query))
    }

    fn category_has_match(&self, id: Uuid) -> bool {
        if self.query.is_empty() {
            return true;
        }
        if self
            .paths
            .get(&id)
            .is_some_and(|path| path.contains(self.query))
        {
            return true;
        }
        if self
            .hosts
            .get(&Some(id))
            .is_some_and(|hosts| hosts.iter().any(|host| self.host_matches(host)))
        {
            return true;
        }
        self.children.get(&Some(id)).is_some_and(|children| {
            children
                .iter()
                .any(|child| self.category_has_match(child.id))
        })
    }
}

fn category_paths(categories: &[Category]) -> HashMap<Uuid, String> {
    let by_id: HashMap<_, _> = categories
        .iter()
        .map(|category| (category.id, category))
        .collect();
    let mut paths = HashMap::with_capacity(categories.len());
    for category in categories {
        let mut labels = vec![category.label.to_lowercase()];
        let mut parent = category.parent_id;
        while let Some(id) = parent {
            let Some(category) = by_id.get(&id) else {
                break;
            };
            labels.push(category.label.to_lowercase());
            parent = category.parent_id;
        }
        labels.reverse();
        paths.insert(category.id, labels.join(" / "));
    }
    paths
}

fn credential_matches(credential: &Credential, query: &str) -> bool {
    query.is_empty()
        || credential.label.to_lowercase().contains(query)
        || credential.username.to_lowercase().contains(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moving_a_selected_host_into_a_collapsed_parent_keeps_selection() {
        let mut vault = Vault::new();
        let credential = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let child = Uuid::new_v4();
        let host = Uuid::new_v4();
        vault.credentials.push(Credential {
            id: credential,
            label: "Agent".into(),
            username: "user".into(),
            auth: Auth::Agent,
        });
        vault.categories.push(Category {
            id: parent,
            label: "Parent".into(),
            parent_id: None,
        });
        vault.categories.push(Category {
            id: child,
            label: "Child".into(),
            parent_id: Some(parent),
        });
        vault.hosts.push(Host {
            id: host,
            label: "Move me".into(),
            hostname: "example.test".into(),
            port: 22,
            category_id: None,
            credential_id: credential,
        });
        let mut catalog = Catalog::default();
        catalog.expanded_sections.insert(Section::Servers);
        catalog.ungrouped_expanded = true;
        catalog.rebuild(&vault, std::iter::empty());
        catalog.select(&RowKey::Host(host));
        vault.hosts[0].category_id = Some(child);
        catalog.invalidate();
        catalog.rebuild(&vault, std::iter::empty());
        assert_eq!(catalog.selected_key(), Some(RowKey::Host(host)));
    }
}

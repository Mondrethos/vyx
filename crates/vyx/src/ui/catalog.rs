use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::vault::{Auth, Category, Credential, Host, HostAuth, Vault};

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
    /// The selection before the first kept filter, restored when that filter is cleared.
    filter_origin: Option<RowKey>,
    /// A selection the next rebuild applies once its rows exist.
    pending: Option<Pending>,
    expanded_categories: HashSet<Uuid>,
    expanded_sections: HashSet<Section>,
    ungrouped_expanded: bool,
    snippets_expanded: bool,
    needs_rebuild: bool,
}

enum Pending {
    /// Expand the record's section and parent categories, then select it.
    Reveal(RowKey),
    /// Select the record only if it is still visible.
    Restore(RowKey),
}

impl Pending {
    fn key(&self) -> &RowKey {
        match self {
            Self::Reveal(key) | Self::Restore(key) => key,
        }
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            selected: 0,
            viewport: 0,
            filter: String::new(),
            filter_origin: None,
            pending: None,
            expanded_categories: HashSet::new(),
            expanded_sections: HashSet::from([
                Section::Sessions,
                Section::Servers,
                Section::Credentials,
                Section::Tools,
                Section::Sync,
            ]),
            ungrouped_expanded: true,
            snippets_expanded: true,
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

    /// A filter is set but no record matches it, so only section headers remain.
    pub fn no_matches(&self) -> bool {
        !self.filter.is_empty() && self.rows.iter().all(|row| matches!(row.key, RowKey::Section(_)))
    }

    /// Remembers the selection that a later `clear_filter` restores.
    pub fn set_filter_origin(&mut self, origin: Option<RowKey>) {
        self.filter_origin = origin;
    }

    /// Clears a kept filter. The next rebuild restores the selection from before the filter
    /// when that row still exists. Returns whether a filter was set.
    pub fn clear_filter(&mut self) -> bool {
        if self.filter.is_empty() {
            return false;
        }
        self.filter.clear();
        self.pending = self.filter_origin.take().map(Pending::Restore);
        self.needs_rebuild = true;
        true
    }

    /// Clears any filter; the next rebuild expands the record's section and parent
    /// categories and selects it.
    pub fn reveal(&mut self, key: RowKey) {
        self.filter.clear();
        self.filter_origin = None;
        self.pending = Some(Pending::Reveal(key));
        self.needs_rebuild = true;
    }

    /// Selects the first matching record, else the first grouping row that matched (a
    /// category, Ungrouped, or Snippets); false when only section headers remain.
    pub fn select_first_match(&mut self) -> bool {
        let record = |row: &CatalogRow| {
            matches!(row.key, RowKey::Session(_) | RowKey::Host(_) | RowKey::Credential(_) | RowKey::Snippet(_) | RowKey::Sync)
        };
        let Some(index) = self.rows.iter().position(record)
            .or_else(|| self.rows.iter().position(|row| !matches!(row.key, RowKey::Section(_))))
        else {
            return false;
        };
        self.selected = index;
        true
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
        let session_count = sessions.len();
        let old_key = self.selected_key();
        let pending = self.pending.take();
        // A moved record remains selected even if its new parent was collapsed.
        if let Some(key @ (RowKey::Host(_) | RowKey::Category(_))) = &old_key {
            self.expand_to(vault, key);
        }
        if let Some(Pending::Reveal(key)) = &pending {
            self.expand_to(vault, key);
        }
        let first_build = old_key.is_none() && self.rows.is_empty();
        let old_index = self.selected;
        let query = self.filter.to_lowercase();
        let filtering = !query.is_empty();
        // Each section's header label with its visible rows; headers are placed below.
        let mut sections = Vec::with_capacity(5);
        let mut rows = Vec::new();

        if self.section_open(Section::Sessions, filtering) {
            for session in sessions {
                if matches_query(&query, [session.label]) {
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
        sections.push((Section::Sessions, format!("Sessions ({session_count})"), std::mem::take(&mut rows)));

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
        sections.push((Section::Servers, format!("Servers ({})", vault.hosts.len()), std::mem::take(&mut rows)));

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
        sections.push((Section::Credentials, format!("Credentials ({})", vault.credentials.len()), std::mem::take(&mut rows)));

        if self.section_open(Section::Tools, filtering) {
            let mut snippets: Vec<_> = vault.snippets.iter().collect();
            snippets.sort_by_cached_key(|entry| (entry.label.to_lowercase(), entry.id));
            let matching: Vec<_> = snippets
                .into_iter()
                .filter(|snippet| {
                    matches_query(&query, [snippet.label.as_str(), snippet.command.as_str()])
                })
                .collect();
            if !filtering || !matching.is_empty() || matches_query(&query, ["snippets"]) {
                let expanded = self.snippets_expanded || filtering;
                rows.push(CatalogRow {
                    key: RowKey::Snippets,
                    label: "Snippets".to_owned(),
                    indent: 1,
                    expandable: true,
                    expanded,
                });
                if expanded {
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
        }
        sections.push((Section::Tools, format!("Tools ({})", vault.snippets.len()), std::mem::take(&mut rows)));

        if self.section_open(Section::Sync, filtering)
            && matches_query(&query, ["sync"])
        {
            rows.push(CatalogRow {
                key: RowKey::Sync,
                label: "Settings and status".to_owned(),
                indent: 1,
                expandable: false,
                expanded: false,
            });
        }
        sections.push((Section::Sync, "Sync".to_owned(), rows));

        // While a filter has matches, headers of sections without any stay hidden; with no
        // match at all every header remains so the list is never blank.
        let matched = filtering && sections.iter().any(|(_, _, children)| !children.is_empty());
        let mut rows = Vec::with_capacity(sections.iter().map(|(_, _, children)| children.len() + 1).sum());
        for (section, label, children) in sections {
            if matched && children.is_empty() {
                continue;
            }
            rows.push(CatalogRow {
                key: RowKey::Section(section),
                label,
                indent: 0,
                expandable: true,
                expanded: self.expanded_sections.contains(&section),
            });
            rows.extend(children);
        }

        self.rows = rows;
        let rows = &self.rows;
        let position = |key: &RowKey| rows.iter().position(|row| &row.key == key);
        let selected = pending
            .as_ref()
            .and_then(|pending| position(pending.key()))
            .or_else(|| old_key.as_ref().and_then(position))
            .unwrap_or_else(|| old_index.saturating_sub(1).min(rows.len().saturating_sub(1)));
        self.selected = selected;
        if first_build
            && session_count == 0
            && vault.categories.is_empty()
            && vault.credentials.is_empty()
            && vault.hosts.is_empty()
            && vault.snippets.is_empty()
        {
            // An empty workspace starts where its first server is added.
            if let Some(index) = self
                .rows
                .iter()
                .position(|row| row.key == RowKey::Section(Section::Servers))
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

    /// Expands the section, group, and parent categories that contain `key`.
    fn expand_to(&mut self, vault: &Vault, key: &RowKey) {
        let mut parent = match key {
            RowKey::Section(_) => None,
            RowKey::Session(_) => {
                self.expanded_sections.insert(Section::Sessions);
                None
            }
            RowKey::Host(id) => {
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
            RowKey::Category(id) => {
                self.expanded_sections.insert(Section::Servers);
                vault
                    .categories
                    .iter()
                    .find(|category| category.id == *id)
                    .and_then(|category| category.parent_id)
            }
            RowKey::Ungrouped => {
                self.expanded_sections.insert(Section::Servers);
                None
            }
            RowKey::Credential(_) => {
                self.expanded_sections.insert(Section::Credentials);
                None
            }
            RowKey::Snippets => {
                self.expanded_sections.insert(Section::Tools);
                None
            }
            RowKey::Snippet(_) => {
                self.expanded_sections.insert(Section::Tools);
                self.snippets_expanded = true;
                None
            }
            RowKey::Sync => {
                self.expanded_sections.insert(Section::Sync);
                None
            }
        };
        while let Some(id) = parent {
            self.expanded_categories.insert(id);
            parent = vault
                .categories
                .iter()
                .find(|category| category.id == id)
                .and_then(|category| category.parent_id);
        }
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
            RowKey::Snippets => {
                self.snippets_expanded = true;
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
            RowKey::Snippets => {
                self.snippets_expanded = false;
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
                RowKey::Snippets => self.snippets_expanded = false,
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
                RowKey::Snippets => self.snippets_expanded = true,
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
        let (credential_label, username) = match &host.auth {
            HostAuth::Credential { credential_id } => self.credentials.get(credential_id)
                .map_or(("", ""), |entry| (entry.label.as_str(), entry.username.as_str())),
            HostAuth::Password { username, .. } | HostAuth::Tailscale { username, .. } => ("", username.as_str()),
        };
        let category = host.category_id.and_then(|id| self.paths.get(&id));
        matches_query(self.query, [
            host.label.as_str(),
            host.hostname.as_str(),
            credential_label,
            username,
            category.map_or("", String::as_str),
        ])
    }

    fn category_has_match(&self, id: Uuid) -> bool {
        if self.query.is_empty() {
            return true;
        }
        if self
            .paths
            .get(&id)
            .is_some_and(|path| matches_query(self.query, [path.as_str()]))
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
    matches_query(query, [credential.label.as_str(), credential.username.as_str()])
}

fn matches_query<const N: usize>(query: &str, fields: [&str; N]) -> bool {
    if query.is_empty() {
        return true;
    }
    let fields = fields.map(str::to_lowercase);
    query.split_whitespace().all(|word| fields.iter().any(|field| field.contains(word)))
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
            transport: crate::vault::HostTransport::Direct,
            category_id: None,
            auth: HostAuth::Credential { credential_id: credential },
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

    #[test]
    fn search_words_cross_metadata_fields_but_never_search_secrets() {
        let mut vault = Vault::new();
        let credential = Uuid::from_u128(1);
        let category = Uuid::from_u128(2);
        let host = Uuid::from_u128(3);
        vault.credentials.push(Credential {
            id: credential,
            label: "Operations".into(),
            username: "deploy".into(),
            auth: Auth::Password { password: crate::vault::Secret::new("hidden-needle") },
        });
        vault.categories.push(Category {
            id: category,
            label: "Production".into(),
            parent_id: None,
        });
        vault.hosts.push(Host {
            id: host,
            label: "Database".into(),
            hostname: "db.example.test".into(),
            port: 22,
            transport: crate::vault::HostTransport::Direct,
            category_id: Some(category),
            auth: HostAuth::Credential { credential_id: credential },
        });
        let mut catalog = Catalog::default();
        catalog.set_filter("  PROD   deploy db  ".into());
        catalog.rebuild(&vault, std::iter::empty());
        assert!(catalog.rows().iter().any(|row| row.key == RowKey::Host(host)));
        catalog.set_filter("prod missing".into());
        catalog.rebuild(&vault, std::iter::empty());
        assert!(!catalog.rows().iter().any(|row| row.key == RowKey::Host(host)));
        catalog.set_filter("hidden-needle".into());
        catalog.rebuild(&vault, std::iter::empty());
        assert!(!catalog.rows().iter().any(|row| matches!(row.key, RowKey::Host(_) | RowKey::Credential(_))));
        vault.hosts[0].auth = HostAuth::Password {
            username: "server-account".into(),
            password: crate::vault::Secret::new("server-only-secret"),
        };
        catalog.set_filter("prod server-account".into());
        catalog.rebuild(&vault, std::iter::empty());
        assert!(catalog.rows().iter().any(|row| row.key == RowKey::Host(host)));
        catalog.set_filter("server-only-secret".into());
        catalog.rebuild(&vault, std::iter::empty());
        assert!(!catalog.rows().iter().any(|row| row.key == RowKey::Host(host)));
        catalog.set_filter("Operations".into());
        catalog.rebuild(&vault, std::iter::empty());
        assert!(!catalog.rows().iter().any(|row| row.key == RowKey::Host(host)));
    }

    #[test]
    fn a_filter_keeps_only_matching_sections_and_counts_ignore_it() {
        let mut vault = Vault::new();
        let category = Uuid::from_u128(1);
        let host = Uuid::from_u128(2);
        vault.categories.push(Category {
            id: category,
            label: "Production".into(),
            parent_id: None,
        });
        vault.hosts.push(Host {
            id: host,
            label: "Database".into(),
            hostname: "db.example.test".into(),
            port: 22,
            transport: crate::vault::HostTransport::Direct,
            category_id: Some(category),
            auth: HostAuth::Password {
                username: "deploy".into(),
                password: crate::vault::Secret::new("unsearched"),
            },
        });
        let mut catalog = Catalog::default();
        catalog.rebuild(&vault, std::iter::empty());
        let servers = |catalog: &Catalog| {
            catalog.rows().iter().find(|row| row.key == RowKey::Section(Section::Servers)).unwrap().label.clone()
        };
        let unfiltered = servers(&catalog);
        catalog.set_filter("data".into());
        catalog.rebuild(&vault, std::iter::empty());
        let keys: Vec<_> = catalog.rows().iter().map(|row| row.key.clone()).collect();
        assert_eq!(keys, [RowKey::Section(Section::Servers), RowKey::Category(category), RowKey::Host(host)]);
        assert!(catalog.select_first_match());
        assert_eq!(catalog.selected_key(), Some(RowKey::Host(host)), "the match, not its category, is selected");
        assert_eq!(servers(&catalog), unfiltered);
        catalog.set_filter("nothing matches".into());
        catalog.rebuild(&vault, std::iter::empty());
        assert!(catalog.no_matches());
        assert_eq!(catalog.rows().len(), 5, "every header remains when nothing matches");
        assert_eq!(servers(&catalog), unfiltered);
    }
}

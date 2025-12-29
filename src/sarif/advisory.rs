use crate::sarif::model::{Location, Message};
use crate::{Kid, Krates};
use rustsec::advisory::Advisory;
use std::fmt::Write as _;

/// Processes an advisory diagnostic and returns the formatted message and resolved locations
pub(crate) fn process_advisory(
    advisory: &Advisory,
    krates_list: &[Kid],
    krates: Option<&Krates>,
    build_locations: impl FnOnce(&[Kid], &Krates) -> Vec<Location>,
) -> (Message, Vec<Location>) {
    let message = format_advisory_message(advisory);
    let locations = resolve_advisory_locations(krates_list, krates, build_locations);
    (message, locations)
}

/// Formats an advisory diagnostic with detailed markdown
fn format_advisory_message(advisory: &Advisory) -> Message {
    let mut md = String::new();
    let meta = &advisory.metadata;

    // Format heading with ID and title on the same line
    md.push_str("# ");
    if let Some(url) = &meta.url {
        write!(&mut md, "[{}]({url})", meta.id).unwrap();
    } else {
        md.push_str(meta.id.as_str());
    }
    md.push_str(" - ");
    md.push_str(&meta.title);
    md.push_str("\n\n");

    // Description section
    md.push_str("## Description\n\n");
    md.push_str(&meta.description);
    md.push_str("\n\n");

    if !advisory.versions.unaffected().is_empty() {
        md.push_str("## Unaffected\n\n");
        for un in advisory.versions.unaffected() {
            writeln!(&mut md, "- `{un}`").unwrap();
        }
        md.push('\n');
    }

    if !advisory.versions.patched().is_empty() {
        md.push_str("## Patched\n\n");
        for un in advisory.versions.patched() {
            writeln!(&mut md, "- `{un}`").unwrap();
        }
        md.push('\n');
    }

    if let Some(affected) = &advisory.affected {
        md.push_str("## Affected\n\n");
        if !affected.functions.is_empty() {
            md.push_str("| Functions | Versions |\n|---|---|\n");
            for (path, reqs) in &affected.functions {
                write!(&mut md, "|`{path}`|").unwrap();

                for (i, req) in reqs.iter().enumerate() {
                    if i > 0 {
                        md.push_str(", ");
                    }
                    write!(&mut md, "`{req}`").unwrap();
                }
                md.push_str("|\n");
            }
            md.push('\n');
        }

        if !affected.arch.is_empty() {
            md.push_str("### Arches\n\n");
            for arch in &affected.arch {
                writeln!(&mut md, "- {}", arch.as_str()).unwrap();
            }
            md.push('\n');
        }

        if !affected.os.is_empty() {
            md.push_str("### Operating Systems\n\n");
            for os in &affected.os {
                writeln!(&mut md, "- {}", os.as_str()).unwrap();
            }
            md.push('\n');
        }
    }

    Message {
        text: meta.title.clone(),
        markdown: Some(md),
    }
}

/// Resolves locations for advisory diagnostics
/// Advisories point to Cargo.lock which gets filtered out by sarif_location,
/// so we always use fallback to root crate locations
fn resolve_advisory_locations(
    krates_list: &[Kid],
    krates: Option<&Krates>,
    build_locations: impl FnOnce(&[Kid], &Krates) -> Vec<Location>,
) -> Vec<Location> {
    if let Some(krates_ref) = krates {
        build_locations(krates_list, krates_ref)
    } else {
        Vec::new()
    }
}


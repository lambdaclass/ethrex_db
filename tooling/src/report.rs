use clap::Parser;
use colored::Colorize;
use prettytable::{Table, row};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Parser)]
pub struct LinesOfCodeReporterOptions {
    #[arg(short, long, help = "Compare detailed reports for PR comments")]
    pub compare: bool,
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct LinesOfCodeReport {
    pub ethrex_db: usize,
    pub detailed_files: HashMap<String, usize>,
}

pub fn pr_message(
    old_report: HashMap<String, usize>,
    new_report: HashMap<String, usize>,
) -> String {
    let sorted_file_paths = {
        let mut keys: Vec<_> = new_report.keys().collect();
        keys.sort();
        keys
    };

    let mut table = Table::new();
    table.add_row(row!["File", "Lines", "Diff"]);

    let mut total_lines_changed: i64 = 0;
    let mut total_lines_added: i64 = 0;
    let mut total_lines_removed: i64 = 0;

    for file_path in sorted_file_paths {
        let current_loc = *new_report.get(file_path).unwrap() as i64;
        let previous_loc = *old_report.get(file_path).unwrap_or(&0) as i64;
        let loc_diff = current_loc - previous_loc;

        if loc_diff == 0 {
            continue;
        }

        if loc_diff > 0 {
            total_lines_added += loc_diff;
        } else {
            total_lines_removed += loc_diff.abs();
        }

        total_lines_changed += loc_diff.abs();

        table.add_row(row![
            file_path,
            current_loc,
            match current_loc.cmp(&previous_loc) {
                std::cmp::Ordering::Greater => format!("+{loc_diff}"),
                std::cmp::Ordering::Less => format!("{loc_diff}"),
                std::cmp::Ordering::Equal => "-".to_owned(),
            }
        ]);
    }

    if total_lines_changed == 0 {
        return "".to_string();
    }

    let mut pr_message = String::new();

    pr_message.push_str("<h2>Lines of code report</h2>\n");
    pr_message.push('\n');

    pr_message.push_str(&pr_message_summary(
        total_lines_added,
        total_lines_removed,
        total_lines_changed,
    ));

    pr_message.push('\n');
    pr_message.push_str("<details>\n");
    pr_message.push_str("<summary>Detailed view</summary>\n");
    pr_message.push('\n');
    pr_message.push_str("```\n");
    pr_message.push_str(&format!("{table}\n"));
    pr_message.push_str("```\n");
    pr_message.push_str("</details>\n");

    pr_message
}

fn pr_message_summary(
    total_lines_added: i64,
    total_lines_removed: i64,
    total_lines_changed: i64,
) -> String {
    let mut pr_message = String::new();

    pr_message.push_str(&format!(
        "Total lines added: `{}`\n",
        match total_lines_added.cmp(&0) {
            std::cmp::Ordering::Greater => format!("{total_lines_added}"),
            std::cmp::Ordering::Less =>
                unreachable!("total_lines_added should never be less than 0"),
            std::cmp::Ordering::Equal => format!("{total_lines_added}"),
        }
    ));
    pr_message.push_str(&format!(
        "Total lines removed: `{}`\n",
        match total_lines_removed.cmp(&0) {
            std::cmp::Ordering::Greater | std::cmp::Ordering::Equal =>
                format!("{total_lines_removed}"),
            std::cmp::Ordering::Less =>
                unreachable!("total_lines_removed should never be less than 0"),
        }
    ));
    pr_message.push_str(&format!(
        "Total lines changed: `{}`\n",
        match total_lines_changed.cmp(&0) {
            std::cmp::Ordering::Greater | std::cmp::Ordering::Equal =>
                format!("{total_lines_changed}"),
            std::cmp::Ordering::Less =>
                unreachable!("total_lines_changed should never be less than 0"),
        }
    ));

    pr_message
}

pub fn slack_message(old_report: LinesOfCodeReport, new_report: LinesOfCodeReport) -> String {
    let ethrex_db_diff = new_report.ethrex_db.abs_diff(old_report.ethrex_db);

    format!(
        r#"{{
    "blocks": [
        {{
            "type": "header",
            "text": {{
                "type": "plain_text",
                "text": "EthrexDB Lines of Code Report"
            }}
        }},
        {{
            "type": "section",
            "text": {{
                "type": "mrkdwn",
                "text": "*ethrex_db:* {} {}"
            }}
        }}
    ]
}}"#,
        new_report.ethrex_db,
        match new_report.ethrex_db.cmp(&old_report.ethrex_db) {
            std::cmp::Ordering::Greater => format!("(+{ethrex_db_diff})"),
            std::cmp::Ordering::Less => format!("(-{ethrex_db_diff})"),
            std::cmp::Ordering::Equal => "".to_string(),
        }
    )
}

pub fn slack_detailed_message(detailed_files: &HashMap<String, usize>) -> String {
    let total_loc: usize = detailed_files.values().sum();
    
    let mut files: Vec<_> = detailed_files.iter().collect();
    files.sort_by_key(|(name, _)| *name);
    
    let mut detailed_text = format!("*Total: {} lines*\n\n", total_loc);
    
    for (file_name, loc) in files {
        detailed_text.push_str(&format!("• `{}`: {} lines\n", file_name, loc));
    }

    format!(
        r#"{{
    "blocks": [
        {{
            "type": "header",
            "text": {{
                "type": "plain_text",
                "text": "EthrexDB Detailed Lines of Code Report"
            }}
        }},
        {{
            "type": "section",
            "text": {{
                "type": "mrkdwn",
                "text": "{}"
            }}
        }}
    ]
}}"#,
        detailed_text
    )
}

pub fn markdown_detailed_report(detailed_files: &HashMap<String, usize>) -> String {
    let total_loc: usize = detailed_files.values().sum();
    
    let mut files: Vec<_> = detailed_files.iter().collect();
    files.sort_by_key(|(name, _)| *name);
    
    let mut markdown = String::new();
    markdown.push_str("# EthrexDB Lines of Code Report\n\n");
    markdown.push_str(&format!("**Total: {} lines**\n\n", total_loc));
    markdown.push_str("## Files breakdown:\n\n");
    
    for (file_name, loc) in files {
        markdown.push_str(&format!("- `{}`: {} lines\n", file_name, loc));
    }
    
    markdown
}

pub fn github_step_summary(old_report: LinesOfCodeReport, new_report: LinesOfCodeReport) -> String {
    let ethrex_db_diff = new_report.ethrex_db.abs_diff(old_report.ethrex_db);

    format!(
        r#"```
EthrexDB Lines of Code Summary
==============================
ethrex_db: {} {}
```"#,
        new_report.ethrex_db,
        match new_report.ethrex_db.cmp(&old_report.ethrex_db) {
            std::cmp::Ordering::Greater => format!("(+{ethrex_db_diff})"),
            std::cmp::Ordering::Less => format!("(-{ethrex_db_diff})"),
            std::cmp::Ordering::Equal => "".to_string(),
        }
    )
}

pub fn shell_summary(new_report: LinesOfCodeReport) -> String {
    format!(
        "{}\n{}\n{} {}",
        "EthrexDB Lines of Code".bold(),
        "======================".bold(),
        "ethrex_db:".bold(),
        new_report.ethrex_db,
    )
}

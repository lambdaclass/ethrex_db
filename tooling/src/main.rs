use std::collections::HashMap;
use std::fs;
use std::path::Path;

use clap::Parser;
use report::{
    LinesOfCodeReport, LinesOfCodeReporterOptions, markdown_detailed_report, pr_message,
    shell_summary, slack_detailed_message,
};
use spinoff::{Color, Spinner, spinners::Dots};
use tokei::{Config, LanguageType, Languages};

mod report;

fn count_lines_of_code() -> (usize, HashMap<String, usize>) {
    let config = Config::default();
    let mut languages = Languages::new();
    let src_path = Path::new("../src");
    languages.get_statistics(&[src_path], &[], &config);

    let mut total_loc = 0;
    let mut detailed_files = HashMap::new();

    if let Some(rust) = languages.get(&LanguageType::Rust) {
        for report in &rust.reports {
            let file_path = report.name.to_string_lossy().to_string();
            if let Some(relative_path) = file_path.strip_prefix("../src/") {
                // Exclude subdirectories in src/
                // Right now, we only count files in the root of src/
                // since the subdirectories are copied from the ethrex repo
                // and we don't know if we will be using them in the future
                if !relative_path.contains("/") {
                    total_loc += report.stats.code;
                    detailed_files.insert(relative_path.to_string(), report.stats.code);
                }
            }
        }
    }

    (total_loc, detailed_files)
}

fn main() {
    let opts = LinesOfCodeReporterOptions::parse();

    let mut spinner = Spinner::new(Dots, "Counting lines of code...", Color::Cyan);

    let (total_loc, detailed_files) = count_lines_of_code();

    spinner.success("Lines of code calculated!");

    let mut spinner = Spinner::new(Dots, "Generating report...", Color::Cyan);

    let new_report = LinesOfCodeReport {
        ethrex_db: total_loc,
        detailed_files: detailed_files.clone(),
    };

    if opts.compare {
        let current_detailed_loc_report = detailed_files;

        let previous_detailed_loc_report: HashMap<String, usize> =
            fs::read_to_string("previous_detailed_loc_report.json")
                .map(|s| serde_json::from_str(&s).unwrap())
                .unwrap_or(current_detailed_loc_report.clone());

        fs::write(
            "detailed_loc_report.txt",
            pr_message(previous_detailed_loc_report, current_detailed_loc_report),
        )
        .unwrap();

        spinner.success("Comparison report generated!");
    } else {
        fs::write(
            "current_detailed_loc_report.json",
            serde_json::to_string(&detailed_files).unwrap(),
        )
        .expect("current_detailed_loc_report.json could not be written");

        // Generate markdown report
        fs::write(
            "loc_report_detailed.md",
            markdown_detailed_report(&detailed_files),
        )
        .expect("loc_report_detailed.md could not be written");

        // Generate Slack detailed report
        fs::write(
            "loc_report_slack_detailed.txt",
            slack_detailed_message(&detailed_files),
        )
        .expect("loc_report_slack_detailed.txt could not be written");

        spinner.success("Detailed report generated!");
        println!("{}", shell_summary(new_report));
        println!("\nDetailed breakdown:");

        let mut files: Vec<_> = detailed_files.iter().collect();
        files.sort_by_key(|(name, _)| *name);

        for (file_name, loc) in files {
            println!("  {}: {} lines", file_name, loc);
        }
    }
}

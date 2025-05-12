use inquire::{MultiSelect, Select, Text};
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;
use windows::Win32::UI::Shell::IsUserAnAdmin;
use colored::*;
use std::sync::OnceLock;
use std::path::PathBuf;
use walkdir::WalkDir;
use std::io;
use std::env;
use std::ffi::OsString;
use indicatif::{ProgressBar, ProgressStyle};
use dialoguer::{Select as DSelect};

static IS_ADMIN: OnceLock<bool> = OnceLock::new();

#[derive(Serialize, Deserialize, Debug)]
struct WingetExport {
    #[serde(rename = "$schema")]
    schema: Option<String>,
    #[serde(rename = "CreationDate")]
    creation_date: Option<String>,
    #[serde(rename = "Sources")]
    sources: Vec<Source>,
    #[serde(rename = "WinGetVersion")]
    winget_version: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Source {
    #[serde(rename = "Packages")]
    packages: Vec<Package>,
    #[serde(rename = "SourceDetails")]
    source_details: Option<SourceDetails>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Package {
    #[serde(rename = "PackageIdentifier")]
    id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SourceDetails {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Identifier")]
    pub identifier: String,
    #[serde(rename = "Argument")]
    pub argument: String,
    #[serde(rename = "Type")]
    pub source_type: String,
}

fn is_running_as_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

fn get_username() -> Option<OsString> {
    env::var_os("USERNAME")
}

fn get_computername() -> Option<OsString> {
    env::var_os("COMPUTERNAME")
}

fn clear_screen() {
    let _ = Command::new("cmd").args(["/C", "cls"]).status();
}

fn pause() {
    let _ = Command::new("cmd").args(["/C", "pause"]).status();
}

fn main_menu() {
    loop {
        clear_screen();
        print_header();

        let options = vec![
            "Applications (WinGet)",
            "User Folder",
            "Exit",
        ];

        let choice = Select::new("Choose a category:", options)
            .prompt()
            .expect("Menu failed");

        match choice {
            "Applications (WinGet)" => winget_menu(),
            "User Folder" => user_menu(),
            "Exit" => break,
            _ => unreachable!(),
        }
    }
}

fn winget_menu() {
    loop {
        clear_screen();
        print_header();

        let options = vec![
            "Export installed apps",
            "Import apps from JSON",
            "Upgrade all apps",
            "Back",
        ];

        let choice = Select::new("Choose an option:", options)
            .prompt()
            .expect("Submenu failed");

        let username = get_username();
        let computername = get_computername();
        let initial_file_name = format!(
            "{}-on-{}-winget-export.json",
            username.unwrap_or_else(|| "UnknownUser".into()).to_string_lossy(),
            computername.unwrap_or_else(|| "UnknownPC".into()).to_string_lossy()
        );

        match choice {
            "Export installed apps" => {
                let output_file = Text::new("Enter filename for export:")
                    .with_initial_value(&initial_file_name)
                    .prompt()
                    .unwrap();

                let export_dir = PathBuf::from("winget-exports");
                fs::create_dir_all(&export_dir).expect("Failed to create export directory");

                let output_path = export_dir.join(output_file);
                export_apps_interactive(&output_path.to_string_lossy());
                pause();
            }

            "Import apps from JSON" => {
                let export_dir = PathBuf::from("winget-exports");

                let entries = match fs::read_dir(&export_dir) {
                    Ok(read_dir) => read_dir
                        .filter_map(Result::ok)
                        .map(|e| e.path())
                        .filter(|p| p.extension().map(|ext| ext == "json").unwrap_or(false))
                        .collect::<Vec<_>>(),
                    Err(_) => {
                        eprintln!("❌ Failed to read winget-exports directory.");
                        pause();
                        continue;
                    }
                };

                if entries.is_empty() {
                    println!("No export files found in '{}'.", export_dir.display());
                    pause();
                    continue;
                }

                let labels: Vec<String> = entries
                    .iter()
                    .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
                    .collect();

                let selected_index = match DSelect::new()
                    .with_prompt("Select a JSON file to import:")
                    .items(&labels)
                    .interact()
                {
                    Ok(i) => i,
                    Err(_) => {
                        eprintln!("❌ Selection cancelled.");
                        return;
                    }
                };

                let selected_path = &entries[selected_index];
                if let Some(path_str) = selected_path.to_str() {
                    import_apps(path_str);
                } else {
                    eprintln!("❌ Failed to convert path to string.");
                }
                pause();
            }

            "Upgrade all apps" => {
                upgrade_all_apps();
                pause();
            }

            "Back" => break,
            _ => unreachable!(),
        }
    }
}


fn user_menu() {
    loop {
        clear_screen();
        print_header();

        let options = vec![
            "Export Personal Files",
            "Export User Files",
            "Import User Files",
            "Back",
        ];

        let choice = Select::new("User Folder Options:", options)
        .with_page_size(10)
            .prompt()
            .expect("Menu failed");

        match choice {
            "Export Personal Files" => export_personal_files(),
            "Export User Files" => advanced_export(),
            "Import User Files" => import_user_files(),
            "Back" => break,
            _ => unreachable!(),
        }
    }
}

fn advanced_export() {
    let home = match dirs::home_dir() {
        Some(dir) => dir,
        None => {
            eprintln!("❌ Home directory not found.");
            return;
        }
    };

    let entries: Vec<PathBuf> = match fs::read_dir(&home) {
        Ok(read_dir) => read_dir.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(e) => {
            eprintln!("❌ Failed to read home directory: {}", e);
            return;
        }
    };

    if entries.is_empty() {
        println!("⚠️ No entries found in home directory.");
        return;
    }

    let labels: Vec<String> = entries.iter().map(|path| {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let size = if path.is_file() {
            fs::metadata(path).map(|m| m.len()).unwrap_or(0)
        } else {
            get_folder_size(path).unwrap_or(0)
        };
        format!("{} ({})", name, format_size(size))
    }).collect();

    let selected = match MultiSelect::new("Select files or folders to export:", labels)
        .with_page_size(30)
        .prompt()
    {
        Ok(s) => s,
        Err(_) => {
            eprintln!("❌ Selection cancelled.");
            return;
        }
    };

    let selected_paths: Vec<_> = entries.into_iter()
        .filter(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            selected.iter().any(|label| label.starts_with(&name))
        })
        .collect();

    if selected_paths.is_empty() {
        println!("⚠️ No items selected. Aborting.");
        return;
    }

    let username = get_username();
    let computername = get_computername();
    let folder_name = format!(
        "{} on {}",
        username.unwrap_or_else(|| "UnknownUser".into()).to_string_lossy(),
        computername.unwrap_or_else(|| "UnknownPC".into()).to_string_lossy()
    );

    let base_export_path = PathBuf::from("exports").join(&folder_name);
    if let Err(e) = fs::create_dir_all(&base_export_path) {
        eprintln!("❌ Failed to create export folder '{}': {}", base_export_path.display(), e);
        return;
    }

    // Count total files for progress bar
    let total_files: u64 = selected_paths.iter().map(|p| {
        if p.is_file() {
            1
        } else {
            WalkDir::new(p).into_iter().filter_map(Result::ok).filter(|e| e.path().is_file()).count()
        }
    }).sum::<usize>() as u64;

    let pb = ProgressBar::new(total_files);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    for path in selected_paths {
        let rel_path = match path.strip_prefix(&home) {
            Ok(rel) => rel,
            Err(e) => {
                eprintln!("⚠️ Failed to get relative path for {}: {}", path.display(), e);
                continue;
            }
        };

        let target_path = base_export_path.join(rel_path);

        if path.is_file() {
            if let Some(parent) = target_path.parent() {
                if let Err(e) = fs::create_dir_all(parent) {
                    eprintln!("⚠️ Failed to create parent dir {}: {}", parent.display(), e);
                    continue;
                }
            }
            if let Err(e) = fs::copy(&path, &target_path) {
                eprintln!("⚠️ Failed to copy file {} → {}: {}", path.display(), target_path.display(), e);
            } else {
                pb.set_message(path.display().to_string());
                pb.inc(1);
            }
        } else if path.is_dir() {
            for entry in WalkDir::new(&path).into_iter().filter_map(Result::ok) {
                let src = entry.path();
                if src.is_file() {
                    let rel = match src.strip_prefix(&home) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("⚠️ Failed to get relative path for {}: {}", src.display(), e);
                            continue;
                        }
                    };
                    let dest = base_export_path.join(rel);
                    if let Some(parent) = dest.parent() {
                        if let Err(e) = fs::create_dir_all(parent) {
                            eprintln!("⚠️ Failed to create dir {}: {}", parent.display(), e);
                            continue;
                        }
                    }
                    if let Err(e) = fs::copy(src, &dest) {
                        eprintln!("⚠️ Failed to copy {} → {}: {}", src.display(), dest.display(), e);
                    } else {
                        pb.set_message(src.display().to_string());
                        pb.inc(1);
                    }
                }
            }
        }
    }

    pb.finish_with_message("✅ Export complete!");
    println!("📁 Copied files to '{}'", base_export_path.display());
    pause();
}

fn export_personal_files() {
    let home = match dirs::home_dir() {
        Some(dir) => dir,
        None => {
            eprintln!("❌ Could not find home directory.");
            return;
        }
    };

    let folders = vec![
        ("Desktop", home.join("Desktop")),
        ("Documents", home.join("Documents")),
        ("Downloads", home.join("Downloads")),
        ("Pictures", home.join("Pictures")),
        ("Music", home.join("Music")),
        ("Videos", home.join("Videos")),
    ];

    let labels: Vec<String> = folders.iter().map(|(name, path)| {
        let size = get_folder_size(path).unwrap_or(0);
        format!("{} ({})", name, format_size(size))
    }).collect();

    let selection = match MultiSelect::new("Select folders to export:", labels)
        .with_page_size(10)
        .prompt()
    {
        Ok(s) => s,
        Err(_) => {
            eprintln!("❌ Selection cancelled.");
            return;
        }
    };

    let selected_paths: Vec<_> = folders.into_iter()
        .filter(|(name, _)| selection.iter().any(|s| s.starts_with(name)))
        .collect();

    if selected_paths.is_empty() {
        println!("⚠️ No folders selected. Aborting.");
        return;
    }

    let username = get_username();
    let computername = get_computername();
    let folder_name = format!(
        "{} on {}",
        username.unwrap_or_else(|| "UnknownUser".into()).to_string_lossy(),
        computername.unwrap_or_else(|| "UnknownPC".into()).to_string_lossy()
    );

    let base_export_path = PathBuf::from("exports").join(&folder_name);
    if let Err(e) = fs::create_dir_all(&base_export_path) {
        eprintln!("❌ Failed to create export folder '{}': {}", base_export_path.display(), e);
        return;
    }

    // Total number of files for progress bar
    let total_files = selected_paths.iter()
        .map(|(_, folder_path)| {
            WalkDir::new(folder_path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .count() as u64
        })
        .sum();

    let pb = ProgressBar::new(total_files);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    for (_label, folder_path) in selected_paths {
        if !folder_path.exists() {
            eprintln!("⚠️ Folder does not exist: {}", folder_path.display());
            continue;
        }

        for entry in WalkDir::new(&folder_path).into_iter().filter_map(Result::ok) {
            let src = entry.path();
            if src.is_file() {
                let rel = match src.strip_prefix(&home) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("⚠️ Failed to get relative path for {}: {}", src.display(), e);
                        continue;
                    }
                };

                let dest = base_export_path.join(rel);

                if let Some(parent) = dest.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        eprintln!("⚠️ Failed to create directory {}: {}", parent.display(), e);
                        continue;
                    }
                }

                if let Err(e) = fs::copy(src, &dest) {
                    eprintln!("⚠️ Failed to copy {} → {}: {}", src.display(), dest.display(), e);
                    continue;
                }

                pb.set_message(src.display().to_string());
                pb.inc(1);
            }
        }
    }

    pb.finish_with_message("✅ Personal files export complete!");
    println!("📁 Copied files to '{}'", base_export_path.display());
    pause();
}

fn import_user_files() {
    let export_base = PathBuf::from("exports");

    let entries = match fs::read_dir(&export_base) {
        Ok(read_dir) => read_dir,
        Err(_) => {
            eprintln!("❌ Failed to read exports folder.");
            return;
        }
    };

    let exported_sets: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();

    if exported_sets.is_empty() {
        println!("No exported sets found.");
        return;
    }

    // Display names to user
    let labels: Vec<String> = exported_sets
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();

    let selected_index = match DSelect::new()
        .with_prompt("Choose an export folder to import from:")
        .items(&labels)
        .default(0)
        .interact()
    {
        Ok(i) => i,
        Err(_) => {
            eprintln!("❌ Selection cancelled.");
            return;
        }
    };

    let selected_export_path = &exported_sets[selected_index];

    // Find all folders/files within that export path
    let entries: Vec<PathBuf> = fs::read_dir(&selected_export_path)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();

    if entries.is_empty() {
        println!("Selected export folder is empty.");
        return;
    }

    // Show selection menu for which folders to import
    let labels: Vec<String> = entries.iter().map(|p| {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let size = get_folder_size(p).unwrap_or(0);
        format!("{} ({})", name, format_size(size))
    }).collect();

    let selected_labels = match MultiSelect::new("Select what to import:", labels)
        .with_page_size(30)
        .prompt()
    {
        Ok(s) => s,
        Err(_) => {
            eprintln!("❌ Selection cancelled.");
            return;
        }
    };

    let selected_paths: Vec<_> = entries.into_iter().filter(|p| {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        selected_labels.iter().any(|label| label.starts_with(&name))
    }).collect();

    if selected_paths.is_empty() {
        println!("No items selected for import.");
        return;
    }

    let total_files = selected_paths.iter().map(|path| {
        if path.is_file() {
            1
        } else if path.is_dir() {
            WalkDir::new(path).into_iter().filter_map(Result::ok).filter(|e| e.path().is_file()).count()
        } else {
            0
        }
    }).sum::<usize>() as u64;

    let pb = ProgressBar::new(total_files);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    for path in selected_paths {
        pb.set_message(path.display().to_string());

        let home = match dirs::home_dir() {
            Some(dir) => dir,
            None => {
                eprintln!("❌ Could not find home directory.");
                return;
            }
        };
        let dest = home.join(path.file_name().unwrap());
        if path.is_file() {
            if let Err(e) = fs::copy(&path, &dest) {
                eprintln!("Failed to copy file {:?} → {:?}: {}", path, dest, e);
                pb.inc(1);
            }
        } else if path.is_dir() {
            for entry in WalkDir::new(&path).into_iter().filter_map(Result::ok) {
                let src = entry.path();
                if src.is_file() {
                    let rel = src.strip_prefix(&path).unwrap();
                    let dest_file = dest.join(rel);
                    if let Some(parent) = dest_file.parent() {
                        fs::create_dir_all(parent).ok();
                    }
                    if let Err(e) = fs::copy(src, &dest_file) {
                        eprintln!("Failed to copy {:?} → {:?}: {}", src, dest_file, e);
                    }
                    pb.inc(1);
                }
            }
        }
    }

    pb.finish_with_message("✅ Import complete!");
    pause();
}
fn get_folder_size(path: &PathBuf) -> io::Result<u64> {
    let mut size = 0;
    for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            size += entry.metadata()?.len();
        }
    }
    Ok(size)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    match bytes {
        b if b >= GB => format!("{:.2} GB", b as f64 / GB as f64),
        b if b >= MB => format!("{:.2} MB", b as f64 / MB as f64),
        b if b >= KB => format!("{:.2} KB", b as f64 / KB as f64),
        b => format!("{} B", b),
    }
}

fn center_text(text: &str, width: usize) -> String {
    let padding = width.saturating_sub(text.len()) / 2;
    format!("{:padding$}{}", "", text, padding = padding)
}

fn print_header() {
    let is_admin: bool = *IS_ADMIN.get_or_init(is_running_as_admin);

    let title = format!("WinMigrator ({})", env!("CARGO_PKG_VERSION"));
    let header_width = title.len() + 10;
    println!("{}", "=".repeat(header_width).blue());
    println!("{}", center_text(&title, header_width).bold().blue());
    println!("{}", "=".repeat(header_width).blue());

    let status = if is_admin {
        "✅ Running as Administrator".green()
    } else {
        "⚠️  Not running as Administrator".yellow()
    };

    let home_dir = dirs::home_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    println!("Status: {}", status);
    println!("Home Directory: {}", home_dir.cyan());
    println!();
}

fn parse_exported_json(path: &str) -> Vec<Package> {
    let content = fs::read_to_string(path).expect("Failed to read JSON file");
    let data: WingetExport = serde_json::from_str(&content).expect("Invalid JSON format");

    data.sources
        .into_iter()
        .flat_map(|s| s.packages.into_iter())
        .collect()
}

fn write_filtered_json(path: &str, packages: Vec<Package>) {
    let source_details = SourceDetails {
        name: "winget".into(),
        identifier: "Microsoft.Winget.Source_8wekyb3d8bbwe".into(),
        argument: "https://cdn.winget.microsoft.com/cache".into(),
        source_type: "Microsoft.PreIndexed.Package".into(),
    };

    let export = WingetExport {
        schema: Some("https://aka.ms/winget-packages.schema.2.0.json".to_string()),
        creation_date: Some(chrono::Utc::now().to_rfc3339()),
        sources: vec![Source {
            packages,
            source_details: Some(source_details),
        }],
        winget_version: Some("1.10.390".to_string()),
    };

    let json = serde_json::to_string_pretty(&export).expect("Failed to serialize JSON");
    std::fs::write(path, json).expect("Failed to write filtered JSON");
}

fn export_apps_interactive(output: &str) {
    let temp_file = "winget-temp-export.json";

    // Run winget export
    let export_result = Command::new("winget")
        .args(["export", "-o", temp_file])
        .output()
        .expect("Failed to run winget export");

    if !export_result.status.success() {
        eprintln!(
            "Winget export failed:\n{}",
            String::from_utf8_lossy(&export_result.stderr)
        );
        return;
    }

    // Parse exported JSON into flat list of packages
    let all_packages = parse_exported_json(temp_file);

    if all_packages.is_empty() {
        eprintln!("No packages found in export.");
        return;
    }

    // Create labels for selection
    let labels: Vec<String> = all_packages
        .iter()
        .map(|p| p.id.clone())
        .collect();

    // Ask user to select apps
    let selected = match MultiSelect::new("Select packages to export:", labels)
    .with_page_size(30)
    .prompt() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Selection cancelled.");
            return;
        }
    };

    // Filter selected packages
    let filtered: Vec<Package> = all_packages
        .into_iter()
        .filter(|p| selected.contains(&p.id))
        .collect();

    if filtered.is_empty() {
        println!("No packages selected. Export cancelled.");
        return;
    }

    // Write new JSON
    write_filtered_json(output, filtered);
    println!("✅ Saved selected packages to '{}'", output);

    let _ = fs::remove_file(temp_file);
}

fn import_apps(path: &str) {
    if !std::path::Path::new(path).exists() {
        eprintln!("File '{}' not found.", path);
        return;
    }

    println!("Running winget import from '{}'", path);

    let status = Command::new("winget")
        .args(["import", "-i", path])
        .status()
        .expect("Failed to run winget import");

    if !status.success() {
        eprintln!("❌ Failed to import apps.");
    } else {
        println!("✅ Apps imported successfully.");
    }
}

fn upgrade_all_apps() {
    println!("Running 'winget upgrade --all'...");

    let status = Command::new("winget")
        .args(["upgrade", "--all"])
        .status()
        .expect("Failed to run 'winget upgrade'");

    if status.success() {
        println!("✅ All upgradable packages were processed.");
    } else {
        eprintln!("❌ Failed to upgrade some or all packages.");
    }
}


fn main() {
    main_menu();
}

use std::io::{stdin,stdout,Write};

// 1. Are you creating an Individual Certificate [1] or an Organization Certificate [2]: 
// 2. Contact:
    // email address (Optional)
    // business address (Optional)
    // phone number (Optional)
// 3. Validility Period
    //

pub struct CreateCertificate;

impl CreateCertificate {
    pub fn new(){
        // Clear Screen
        print!("\x1B[2J");

        // Introduction
        println!("Selenite Key Generation (v0.1.0):")
        println!("by @AtropineTears | OpenNightshade")
        println!();
        println!("Do you want to Generate a SimpleCertificate for Code-Signing [y/n]: ")
        let input = io::stdin()
                            .read_line(&mut number)
                            .expect("Failed to read input");
        if input == "Y" || input = "y" || input = "yes" || input = "Yes" || input = "YES" || input = "YeS" {

        }
        else if input == "N" || input == "n" || input == "no" || input == "No" || input == "NO" {

        }
        else {
            
        }
    }
}

// 1. Would You Like To Generate A Certificate? [y/n]
    // Is it an individual [1] or organization [2]?
    // Subject Name: 
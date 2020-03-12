extern crate rand;

mod lib;

use std::io;
use std::io::prelude::*;
use std::fs::OpenOptions;
use std::ptr;
use std::mem;
use libc;

use std::any::type_name;

include!("lib/falcon.rs");

fn main() {
    println!("******************************");
    println!(" --  Test of Task 1  --  ");
    println!("Please input test method.");
    println!("  1 - Test step by step.");
    println!("  2 - Test and save result into files.");
    println!("  3 - Exit.");
    println!("******************************");
    
    loop {
        let mut test_method = String::new();

        io::stdin().read_line(&mut test_method)
            .expect("Faildd to read line.");

        let test_method: u32 = match test_method.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };

        match test_method {
            2 => {
                println!("You set Test Method 2.");
                generate_test_file();
                println!("Test Method 1 was completed.\n");
                println!("If you input test method again, you can continue to test.");
                println!("  1 - Test and save result into files.");
                println!("  2 - Test step by step.");
                println!("  3 - Exit.");
            },
            1 => {
                println!("You set Test Method 1.");
                println!("******************************");
                println!("Please input test step.");
                println!("  1 - Generate Multiple Private-Public key pairs.");
                println!("  2 - Generate Random data and Sign with Private keys.");
                println!("  3 - Verify signatures using public key(s).");
                println!("  4 - Exit.");

                let mut tested_step1 = false;
                let mut tested_step2 = false;

                let mut seed: [u8; 48] = [0; 48];
                let mut msg: [u8; 3300] = [0; 3300];
                let mut entropy_input: [u8; 48] = [0; 48];
                let mut m: *mut u8 = ptr::null_mut();
                let mut mlen: u64 = 33;
                let mut m1: *mut u8 = ptr::null_mut();
                let mut mlen1: u64 = 33;
                let mut sm: *mut u8 = ptr::null_mut();
                let mut smlen: u64 = 33;
                
                let mut pk: [u8; CRYPTO_PUBLICKEYBYTES as usize] = [0; CRYPTO_PUBLICKEYBYTES as usize];
                let mut sk: [u8; CRYPTO_SECRETKEYBYTES as usize] = [0; CRYPTO_SECRETKEYBYTES as usize];

                unsafe {
                    m = libc::calloc(mlen as usize, mem::size_of::<u8>()) as *mut u8;
                    m1 = libc::calloc(mlen as usize, mem::size_of::<u8>()) as *mut u8;
                    sm = libc::calloc((mlen as usize) + (CRYPTO_BYTES as usize), mem::size_of::<u8>()) as *mut u8;
                }

                // Initialize
                for i in 0..48 {
                    entropy_input[i] = i as u8;
                    // entropy_input[i] = rand::thread_rng().gen_range(0, 48) as u8;
                }

                unsafe {
                    randombytes_init(entropy_input.as_mut_ptr(), ptr::null_mut(), 256);
                }

                // Generate random seed
                unsafe {
                    randombytes(seed.as_mut_ptr(), 48);
                }

                loop {
                    let mut unit_step = String::new();
                    
                    io::stdin().read_line(&mut unit_step)
                        .expect("Faildd to read line.");

                    let unit_step: u32 = match unit_step.trim().parse() {
                        Ok(num) => num,
                        Err(_) => continue,
                    };

                    match unit_step {
                        1 => {
                            println!("Test unit 1 : \"Generate Multiple Private-Public key pairs\".");

                            test_unit_one(&mut seed, &mut pk, &mut sk);
                            tested_step1 = true;
                            tested_step2 = false;

                            println!("Test step 1 was completed");
                            println!("Please input test step.");
                            println!("  1 - Generate Multiple Private-Public key pairs.");
                            println!("  2 - Generate Random data and Sign with Private keys.");
                            println!("  3 - Verify signatures using public key(s).");
                            println!("  4 - Exit.");
                        },
                        2 => {
                            println!("Test unit 2 : \"Generate Random data and Sign with Private keys\".");

                            if tested_step1 == false {
                                test_unit_one(&mut seed, &mut pk, &mut sk);
                                tested_step1 = true;
                            }

                            // Input message length
                            println!("\nPlease input Message length to generate.");
                            
                            loop {
                                let mut msg_len = String::new();
                                                
                                io::stdin().read_line(&mut msg_len)
                                    .expect("Faildd to read line.");

                                match msg_len.trim().parse() {
                                    Ok(num) => { mlen = num; break },
                                    Err(_) => { println!("\nPlease input correct number."); continue },
                                };
                            }

                            if mlen < 0 {
                                mlen = 0;
                            }

                            // Generate random message
                            if m == ptr::null_mut() {
                                unsafe { libc::free(m as *mut libc::c_void) };
                            }

                            if m1 == ptr::null_mut() {
                                unsafe { libc::free(m1 as *mut libc::c_void) };
                            }

                            if sm == ptr::null_mut() {
                                unsafe { libc::free(sm as *mut libc::c_void) };
                            }

                            unsafe {
                                m = libc::calloc(mlen as usize, mem::size_of::<u8>()) as *mut u8;
                                m1 = libc::calloc(mlen as usize, mem::size_of::<u8>()) as *mut u8;
                                sm = libc::calloc((mlen as usize) + (CRYPTO_BYTES as usize), mem::size_of::<u8>()) as *mut u8;
                            }

                            test_unit_two(&mut sk, sm, &mut smlen, m, &mut mlen);
                            tested_step2 = true;

                            println!("Test unit 2 was completed");
                            println!("Please input test step.");
                            println!("  1 - Generate Multiple Private-Public key pairs.");
                            println!("  2 - Generate Random data and Sign with Private keys.");
                            println!("  3 - Verify signatures using public key(s).");
                            println!("  4 - Exit.");
                        },
                        3 => {
                            println!("Test unit 3 : \"Verify signatures using public key(s)\".");

                            if tested_step1 == false {
                                test_unit_one(&mut seed, &mut pk, &mut sk);
                                tested_step1 = true;
                            }

                            if tested_step2 == false {
                                test_unit_two(&mut sk, sm, &mut smlen, m, &mut mlen);
                                tested_step2 = true;
                            }
                            
                            // unsafe { *m.offset((mlen - 1) as  isize) = 0x55; }
                            
                            let check_verify = test_unit_three(&mut pk, m, &mut mlen, sm, &mut smlen, m1, &mut mlen1);
                            
                            match check_verify {
                                0 => println!("\nVerify the message successfully.\n"),
                                1 => println!("\nMessage lengths are not the same.\n"),
                                2 => println!("\nMessage contents are not the same.\n"),
                                _ => println!("\nFail in calculation. {} \n", check_verify),
                            }

                            println!("Test uint 3 was completed");
                            println!("Please input test step.");
                            println!("  1 - Generate Multiple Private-Public key pairs.");
                            println!("  2 - Generate Random data and Sign with Private keys.");
                            println!("  3 - Verify signatures using public key(s).");
                            println!("  4 - Exit.");
                        },
                        4 => {
                            println!(" ---  Test Method 2 exits !  --- ");
                            break;
                        },
                        _ => {
                            println!("Please input correct number!");
                        }
                    }
                }

                unsafe { libc::free(m as *mut libc::c_void) };
                unsafe { libc::free(m1 as *mut libc::c_void) };
                unsafe { libc::free(sm as *mut libc::c_void) };

                println!("Test Method 2 was completed.\n");
                println!("If you input test method again, you can continue to test.");
                println!("  1 - Test and save result into files.");
                println!("  2 - Test step by step.");
                println!("  3 - Exit.");
            },
            3 => {
                println!("   ---  Exit. Bye!  ---  ");
                break;
            },
            _ => {
                println!("Please input correct number!");
            }
        }
    }    
}

/**
 *  Test unit 1 - Generate Multiple Private-Public key pairs
*/
fn test_unit_one(seed: &mut [u8], pk: &mut [u8], sk: &mut [u8]) {

    // Generate random seed
    unsafe {
        randombytes(seed.as_mut_ptr(), 48);
    }

    // Generate the public/private keypair.
    let mut ret_val = lib::api::nist_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    if ret_val != 0 {
        println!("crypto_sign_keypair returned <{}>\n", ret_val);
        return;
    }

    // Display private key
    print!("\nPrivate Key ( length :  {} ) = ", pk.len());
    for i in 0..pk.len() {
        print!("{:02X}", pk[i]);
    }
    print!(";\n");

    // Display public key
    print!("\nPublic Key ( length :  {} ) = ", sk.len());
    for i in 0..sk.len() {
        print!("{:02X}", sk[i]);
    }
    print!(";\n");
}

/**
 *  Test unit 2 - Generate Random data and Sign with Private keys
*/
fn test_unit_two(sk: &mut [u8], sm: *mut u8, smlen: &mut u64, m: *mut u8, mlen: &mut u64) {

    unsafe {
        randombytes(m, *mlen);
    }

    // Sign
    let ret_val = lib::api::nist_crypto_sign(sm, smlen, m, *mlen, sk.as_mut_ptr());
    if ret_val != 0 {
        println!("crypto_sign returned <{}>\n", ret_val);
        return;
    }

    unsafe {
        // Display message
        print!("\nMessage ( length :  {} ) = ", mlen);
        for i in 0..*mlen {
            print!("{:02X}", *m.offset(i as isize));
        }
        print!(";\n");

        // Display Signed message
        print!("\nSigned message ( length :  {} ) = ", smlen);
        for i in 0..*smlen {
            print!("{:02X}", *sm.offset(i as isize));
        }
        print!(";\n");
    }
}

/**
 *  Test unit 3 - Verify signatures using public key(s)
*/
fn test_unit_three(pk: &mut [u8], m: *mut u8, mlen: &mut u64, sm: *mut u8, smlen: &mut u64, m1: *mut u8, mlen1: &mut u64) -> i32 {
    
    // Verify
    let ret_val = lib::api::nist_crypto_sign_open(m1, mlen1, sm, *smlen, pk.as_mut_ptr());
    if ret_val != 0 {
        return ret_val;
    }
    
    unsafe {
        // Display verified message
        print!("\nVerified message ( length :  {} ) = ", *mlen1);
        for i in 0..*mlen1 {
            print!("{:02X}", *m1.offset(i as isize));
        }
        print!(";\n");
    }

    if *mlen != *mlen1 {
        return 1;
    }

    // Compare m and m1
    let mut eqmem: bool = false;
    for i in 0..*mlen {
        unsafe {
            if *m.offset(i as isize) != *m1.offset(i as isize) {
                eqmem = true;
                break;
            }
        }
    }
    if eqmem {
        return 2;
    }

    return 0;
}

/**
 * Test the Task 1 and save the result into files *.req and *.rep.
 * In this test, 
 * First, 5 pairs of private and public keys are generated,
 * Second, 5 random data are generated.
 * Third, the generated data are signed and verified.
 * Finally, all the results are saved into files *.req and *.rep.
 * *.req : a file which has 5 pairs of private and public keys.
 * *.rep : a file which has all the results.
 * 
*/
fn generate_test_file() {
    let mut seed: [u8; 48] = [0; 48];
    let mut msg: [u8; 3300] = [0; 3300];
    let mut entropy_input: [u8; 48] = [0; 48];
    let mut m: *mut u8 = ptr::null_mut();
    let mut mlen: u64 = 0;
    let mut m1: *mut u8 = ptr::null_mut();
    let mut mlen1: u64 = 0;
    let mut sm: *mut u8 = ptr::null_mut();
    let mut smlen: u64 = 0;
    let mut count: i32 = 0;
    let mut done: i32 = 0;
    
    let mut pk: [u8; CRYPTO_PUBLICKEYBYTES as usize] = [0; CRYPTO_PUBLICKEYBYTES as usize];
    let mut sk: [u8; CRYPTO_SECRETKEYBYTES as usize] = [0; CRYPTO_SECRETKEYBYTES as usize];
    
    // Create the REQUEST file
    let fn_req = format!("PQCsignKAT_{}.req", CRYPTO_SECRETKEYBYTES);
    let mut fp_req = match OpenOptions::new().write(true).create(true).append(false).open(fn_req) {
        Err(why) => panic!("Couldn't open <PQCsignKAT_{}.req> for write: {}\n", CRYPTO_SECRETKEYBYTES, why),
        Ok(file) => file,
    };
    
    let fn_rsp = format!("PQCsignKAT_{}.rsp", CRYPTO_SECRETKEYBYTES);
    let mut fp_rsp = match OpenOptions::new().write(true).create(true).append(false).open(fn_rsp) {
        Err(why) => panic!("Couldn't open <PQCsignKAT_{}.rsp> for write: {}\n", CRYPTO_SECRETKEYBYTES, why),
        Ok(file) => file,
    };

    // Create random request
    for i in 0..48 {
        entropy_input[i] = i as u8;
    }

    unsafe {
        randombytes_init(entropy_input.as_mut_ptr(), ptr::null_mut(), 256);
    }

    for i in 0..5 {
        match fp_req.write(format!("count = {:<5}\n", i).as_bytes()) {
            Err(err) => panic!("Couldn't write: {}", err),
            Ok(n) => n, 
        };

        unsafe {
            randombytes(seed.as_mut_ptr(), 48);
        }
        lib::api::fprintBstr(&mut fp_req, ("seed = ").to_string(), seed.as_mut_ptr(), 48);

        mlen = 33 * (i + 1);
        fp_req.write(format!("mlen = {:<5}\n", mlen).as_bytes()).expect("Couldn't write");

        unsafe {
            randombytes(msg.as_mut_ptr(), mlen);
        }
        lib::api::fprintBstr(&mut fp_req, ("msg = ").to_string(), msg.as_mut_ptr(), mlen);
        fp_req.write(format!("pk = \n").as_bytes()).expect("Couldn't write");
        fp_req.write(format!("sk = \n").as_bytes()).expect("Couldn't write");
        fp_req.write(format!("smlen = \n").as_bytes()).expect("Couldn't write");
        fp_req.write(format!("sm = \n\n").as_bytes()).expect("Couldn't write");        
    }

    drop(fp_req);

    //Create the RESPONSE file based on what's in the REQUEST file
    let fn_req = format!("PQCsignKAT_{}.req", CRYPTO_SECRETKEYBYTES);
    let mut fp_req = match OpenOptions::new().read(true).open(fn_req) {
        Err(why) => panic!("\nCouldn't open <PQCsignKAT_{}.req> for read: {}\n", CRYPTO_SECRETKEYBYTES, why),
        Ok(file) => file,
    };
    
    fp_rsp.write(format!("# Falcon-512\n\n").as_bytes()).expect("\nCouldn't write response file\n");

    done = 0;    
    while done == 0 {
        let mut res = lib::api::FindMarker(&mut fp_req, ("count = ").to_string());
        if res > 0 {
            let mut num_line: [u8; 5] = [0; 5];
            fp_req.read(&mut num_line).unwrap();
            
            let res_str = String::from_utf8(num_line.to_vec()).unwrap();
            count = res_str.trim().parse::<i32>().unwrap();
        } else {
            done = 1;
            break;
        }

        fp_rsp.write(format!("count = {}\n", count).as_bytes()).expect("Couldn't write");
        
        res = lib::api::ReadHex(&mut fp_req, seed.as_mut_ptr(), 48, "seed = ".to_string());
        if res == 0 {
            println!("\nERROR: unable to read 'seed' from {}\n", res);
            return;
        }

        lib::api::fprintBstr(&mut fp_rsp, String::from("seed = "), seed.as_mut_ptr(), 48);
        
        unsafe { lib::api::randombytes_init(seed.as_mut_ptr(), ptr::null_mut(), 256); }
        
        res = lib::api::FindMarker(&mut fp_req, "mlen = ".to_string());
        if res > 0 {
            let mut num_line: [u8; 5] = [0; 5];
            fp_req.read(&mut num_line).unwrap();
            
            let res_str = String::from_utf8(num_line.to_vec()).unwrap();
            mlen = res_str.trim().parse::<u64>().unwrap();
        } else {
            println!("ERROR: unable to read 'mlen'\n");
            return;
        }
        
        fp_rsp.write(format!("mlen = {}\n", mlen).as_bytes()).expect("Couldn't write");
        
        unsafe {
            m = libc::calloc(mlen as usize, mem::size_of::<u8>()) as *mut u8;
            m1 = libc::calloc(mlen as usize, mem::size_of::<u8>()) as *mut u8;
            sm = libc::calloc((mlen as usize) + (CRYPTO_BYTES as usize), mem::size_of::<u8>()) as *mut u8;
        }

        res = lib::api::ReadHex(&mut fp_req, m, mlen as u32, String::from("msg = "));
        if res == 0 {
            println!("ERROR: unable to read 'msg' \n");
            return;
        }
        lib::api::fprintBstr(&mut fp_rsp, String::from("msg = "), m, mlen);
        
        // Generate the public/private keypair.
        let mut ret_val = lib::api::nist_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        if ret_val != 0 {
            println!("crypto_sign_keypair returned <{}>\n", ret_val);
            return;
        }
        lib::api::fprintBstr(&mut fp_rsp, String::from("pk = "), pk.as_mut_ptr(), CRYPTO_PUBLICKEYBYTES as u64);
        lib::api::fprintBstr(&mut fp_rsp, String::from("sk = "), sk.as_mut_ptr(), CRYPTO_SECRETKEYBYTES as u64);       
        
        // Sign
        ret_val = lib::api::nist_crypto_sign(sm, &mut smlen, m, mlen, sk.as_mut_ptr());
        if ret_val != 0 {
            println!("crypto_sign returned <{}>\n", ret_val);
            return;
        }
        fp_rsp.write(format!("smlen = {}\n", smlen).as_bytes()).expect("Couldn't write");
        lib::api::fprintBstr(&mut fp_rsp, String::from("sm = "), sm, smlen);
        fp_rsp.write(format!("\n").as_bytes()).expect("Couldn't write");
        
        // Verify
        ret_val = lib::api::nist_crypto_sign_open(m1, &mut mlen1, sm, smlen, pk.as_mut_ptr());
        if ret_val != 0 {
            println!("crypto_sign_open returned <{}>\n", ret_val);
            return;
        }
        
        if mlen != mlen1 {
            println!("crypto_sign_open returned bad 'mlen': Got <{}>, expected <{}>\n", mlen1, mlen);
            return;
        }
        
        // Compare m and m1
        let mut eqmem: bool = false;
        for i in 0..mlen {
            unsafe {
                if *m.offset(i as isize) != *m1.offset(i as isize) {
                    eqmem = true;
                    break;
                }
            }
        }
        if eqmem {
            println!("crypto_sign_open returned bad 'm' value\n");
            return;
        }
        
        unsafe { libc::free(m as *mut libc::c_void) };
        unsafe { libc::free(m1 as *mut libc::c_void) };
        unsafe { libc::free(sm as *mut libc::c_void) };
    };
    
    drop(fp_req);
    drop(fp_rsp);
}
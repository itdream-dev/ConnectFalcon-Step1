# ConnectFalcon-Step1

#### Development

1. Build
    - On Window:
        - Install OpenSSL via https://slproweb.com/products/Win32OpenSSL.html.

        - Check and Modify OpenSSL install path in build.rs.

            ```
            .include("$INSTALL_PATH/include")
            ```
            ```
            println!("cargo:rustc-link-search=static=$INSTALL_PATH/
            lib");
            ```
            
        - Run "cargo build" in console.

2. Run
    - On Window:
        > Run "cargo run" in console.

3. Test

    There are 2 ways to test Task 1. 
    -  Test step by step
        - Step 1 : Generate Multiple Private-Public key pairs.
        - Step 2 : Generate Random data and Sign with Private keys.
        - Step 3 : Verify signatures using public key(s).

    - Test and save test results into certain files which place in root of project folder.
        
        This method is that all steps run once and the result is saved into files.

        The result is saved into 2 files, which extensions are separately "*.req" and "*.rsp".
        
        The \*.req file contains 5 sets of only seed and random message.        
        The \*.rsp file contains 5 sets of all result such as seed, random message, key pairs, signed message and verified message.

        

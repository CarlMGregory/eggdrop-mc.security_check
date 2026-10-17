##
# Security check 1.2 by MC_8 - Carl M. Gregory <gregory@worldinter.net>
##

# DCC commands (for +m's and up)
#___________________________________
# .purge time <# in days> - will purge (remove) anyone not seen by the bot in x ammount of days
# .purge nopass           - will purge (remove) anyone with NO password
# .chk [option]           - preforms a major scan of your user file, it will report security
#                            alearts to you, but will not remove it (it's your call on 
#                            removing the user, I just make it aware to you!)
#                [option] - +gop - shows global ops
#                           -gop - doesn't show global ops
#                            ^- If one of these are not specified, it will go with
#                               the default setting, ie... what you have set in
#                               purge(list_gop) ((it's below)).


## Protected on .purge time ...
## Imagine a space as an OR, if it's +b OR +mn ..... can have as much as you like
set purge(time_flag) "b mn S"

## Protected on .purge nopass ...
## Imagine a space as an OR, if it's +b OR +mn ..... can have as much as you like
set purge(pass_flag) "b S"

## [1=yes/0=no] ((DEFAULT)) Do you want to list global ops at end of scan (.chk)?
set purge(list_gop) 0

# [1=yes/0=no] Do you want the check points to be viewed upon scan (.chk) ?
set purge(show_chkp) 0

##################
# USERFILE PURGE #
##################

proc master_purge {h i t} {
 global purge
 switch -- [lindex $t 0] {
  time { 
   putlog "Purging user file..."
   foreach hand [userlist] {
    set args [getuser $hand LASTON]
    set text [split $args]
    set lasttime [lindex $text 0]
    if {$lasttime == ""} {
     set lasttime 0
    }
    set handage [expr [unixtime] - $lasttime]
    set purgedays [expr [lindex $t 1] * 86400]
    if {$handage > $purgedays} {
     foreach flag $purge(time_flag) {
      if {[matchattr $hand $flag]} {
       set noticed($hand) 1
       putlog "$hand saved from purging (Protected)"
      } {
       if {![info exists noticed($hand)]} {
        set noticed($hand) 1
        putlog "$hand purged (not seen in $t days)"
        deluser $hand
       }
      }
     }
    }
   }
  }
  nopass { 
   putlog "Purging user file..."
   foreach hand [userlist] {
    set args [getuser $hand PASS]
    if {$args == ""} {
     foreach flag $purge(pass_flag) {
      if {[matchattr $hand $flag]} {
       set noticed($hand) 1
       putlog "$hand saved from purging (Protected)"
      } {
       if {![info exists noticed($hand)]} {
        set noticed($hand) 1
        putlog "$hand purged (no password)"
        deluser $hand
       }
      }
     }
    }
   }
  }
  default { 
   putlog "Purge failed..."
   putidx $i "STNTAX: .purge time <days>"
   putidx $i "SYNTAX: .purge nopass"
   return 0
  }
 }
 if {[info exists noticed]} {unset noticed}
 putlog "Purge Complete."
}
bind dcc m purge master_purge
bind dcc m chk master_check

proc master_check {hand idx args} {
 global purge
 set risk 0
 putidx $idx "Performing security checks..."
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - checking *!*@xxx.xxx.xxx.* users..."
 }
 foreach person [userlist] { 
  foreach host [getuser $person HOSTS] { 
   if {"[string range $host 0 3]x[string index $host [expr [string length $host] - 1]]" == "*!*@x*"} { 
    putidx $idx "13SECURITY RISK: $person is at $host"
    incr risk 1
   }
  }
 }
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - *!*@xxx.xxx.xxx.* user check complete."
  putidx $idx " - checking *!*@*xxx users..."
 }
 foreach person [userlist] { 
  foreach host [getuser $person HOSTS] { 
   if {[string range $host 0 4] == "*!*@*"} { 
    putidx $idx "13SECURITY RISK: $person is at $host"
    incr risk 1
   }
  }
 }
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - *!*@*xxx check complete."
  putidx $idx " - checking xxx!xxx@* users..."
 }
 foreach person [userlist] { 
  foreach host [getuser $person HOSTS] { 
   if {[string range $host [expr [string length $host] - 2] end] == "@*"} { 
    putidx $idx "13SECURITY RISK: $person is at $host"
    incr risk 1
   }
  }
 }
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - xxx!xxx@* check complete."
  putidx $idx " - checking for ppl with no password..."
 }
 foreach hand [userlist] {
  if {[getuser $hand PASS] == ""} {
   putidx $idx "13SECURITY RISK: $hand has no password"
   incr risk 1
  }
 }
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - no password check complete."
  putidx $idx " - checking users passwords..."
 }
 foreach hand [userlist] {
  if {([passwdok $hand $hand]) && ([getuser $hand PASS] != "")} {
   putidx $idx "13SECURITY RISK: $hand's password is $hand, same as handle"
   incr risk 1
  }
 }
# added catch for limbo security check support
 catch {
  foreach chan [channels] {
   foreach user [chanlist $chan] {
    if {([validuser [nick2hand $user $chan]]) &&
        ([passwdok [nick2hand $user $chan] $user]) &&
        ([nick2hand $user $chan] != $user) &&
        (![info exists noticed($user)]) &&
        ([getuser $hand PASS] != "")} {
     putidx $idx "13SECURITY RISK: $user (hand: [nick2hand $user $chan])'s password is $user, same as IRC nick"
     set noticed($user) 1
     incr risk 1
    }
   }
  }
 }
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - user password check complete."
  putidx $idx " - checking for global +a's..."
 }
 foreach hand [userlist] {
  if {[matchattr $hand a]} {
   putidx $idx "13SECURITY RISK: $hand has a global +a"
   incr risk 1
  }
 }
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - global +a check complete."
  putidx $idx " - checking for all channel +a's..."
 }
 foreach hand [userlist] {
  foreach chan [channels] {
   if {[matchattr $hand |a $chan]} {
    putidx $idx "13SECURITY RISK: $hand has +a in $chan"
    incr risk 1
   }
  }
 }
 if {$purge(show_chkp) == "1"} {
  putidx $idx " - channel +a check complete."
 }
 if {(($purge(list_gop)) && (![string match *-gop* $args])) ||
     ([string match *+gop* $args])} {
  if {$purge(show_chkp) == "1"} {
   putidx $idx " - listing global +o's (global ops!)"
  } ; set temp 0
  foreach hand [userlist] {
   if {[matchattr $hand o]} {
    putidx $idx "Global Op #[set temp [incr temp +1]]: $hand"
   }
  } ; unset temp
  if {$purge(show_chkp) == "1"} {
   putidx $idx " - global +o listing complete."
  }
 }
 if {[info exists noticed]} {unset noticed}
 putidx $idx "Security checks complete. Security Risks: 13$risk"
}
if {[info exists noticed]} {unset noticed}

putlog " - Security Check 1.2 by MC_8"


##
# Security Check v2.0.2
#  by MC_8 - Carl M. Gregory <mc8@purehype.net>
#  This script will only run on eggdrop 1.6.14 or greater.
#
#    R.I.P. Mom, To always be remembered; Nancy Marie Gregory.
#
# My Website - http://mc.purehype.net/
# Have a bug, script not working correctly, or just an idea?
#   http://mc.purehype.net/bugzilla/
# Have a question?
#   http://forum.purehype.net/viewforum.php?f=5
##

##
# Description
##
# This script will add a DCC command of '.security_check' to check different
# points of userfile security.  If anything looks insecure when running the
# command, it will show you.
##

##
# Commands
##
# For a list of valid commands, see '.help mc.security_check' within DCC chat
# with your bot once this script is loaded.
##

##
# Configuration
##
#

# Who is allowed to have access to the security_check DCC command?  Specify
# only global flags required.  In DCC chat with your bot, you can type
# '.help whois' to see a list of valid flags and there definitions.
# Example:  "t"  This means only those who have the t flag, botnet masters.
#           "n"  This means only those who have the n flag, owner.
set mc_secchk(:config:dcc_access) "t"

## SVS Client (Script Version Service) v4.1.2 ##
# Once a day, the SVS Client will connect to MC_8's SVS Server to determine if
# there is a newer version of this script available.  If a newer version is
# found, the script will be auto updated.

# [0=no/1=yes] Do you want to enable auto updating?  If you chose to disable
# auto updating, it will not automatically update the script upon finding a
# newer version.
set mc_secchk(:config:svs:enable) 1

#
##

##
# Done with configurations, do not edit past here unless you know TCL.
##
#

## SVS insert (pre code)
#Script:mc_secchk
catch {unset temp}

foreach temp(bind) [binds mc:secchk:*] {
  foreach {temp(1) temp(2) temp(3) temp(4) temp(5)} $temp(bind) break
  catch {unbind $temp(1) $temp(2) $temp(3) $temp(5)}
}

set mc_secchk(info:vars) ""
foreach {temp(name) temp(value)} [array get mc_secchk :config:*] {
  lappend mc_secchk(info:vars) [list $temp(name) $temp(value)]
}
set mc_secchk(info:loc) [info script]
array set mc_secchk [list \
  script                 "Security Check" \
  version                "v2.0.2" \
  svs:script             "security_check" \
  svs:version            "002000002000" \
  svs:client_version     "v4.1.2" \
  svs:client_svs_version "004001002000" \
  svs:server             "mc.svs.purehype.net" \
  svs:port               "80" \
  svs:get                "/index.tcl"]
set mc_secchk(svs:query)    "svs=$mc_secchk(svs:script)&"
append mc_secchk(svs:query) "version=$mc_secchk(svs:version)&"
append mc_secchk(svs:query) \
  "svs_version=$mc_secchk(svs:client_svs_version)"

if {![info exists numversion] || 
    ([string range $numversion 0 4] < "10614") ||
    (([string range $numversion 0 4] == "10614") &&
     ([string range $numversion 5 6] != "00"))} {
  set temp(tag) "$mc_secchk(script) $mc_secchk(version)"
  putloglev o * \
    "$temp(tag) by MC_8 will only work on eggdrop 1.6.14 (stable) or greater."
  putloglev o * "$temp(tag) will not work with eggdrop $version."
  putloglev o * "$temp(tag) not loaded."
  uplevel #0 {
    if {[info exists temp] && ![array exists temp]} {unset temp}
    set temp(svs_return) [list 0 "Need to upgrade eggdrop."]
  }; return 1
}
## ^

# Configuration variable sanity.
foreach {temp(a) temp(b)} [list :config:dcc_access     "t"] {
  if {![info exists mc_secchk($temp(a))]} {
    set mc_secchk($temp(a)) $temp(b)
  }
}
if {$mc_secchk(:config:dcc_access) == ""} {
  set mc_secchk(:config:dcc_access) "t"
}
#

# Error Catching System (ECS), v4.1.
proc mc:secchk:errchk {command args} {
  
  # Enable (1) or disable (0) auto reporting of bugs to mc8@purehype.net.
  # This setting here for those who want to disable it in fear of privacy
  # violations.
  set enable_auto_reporting 1
  
  if {![info exists ::lastCommand]} {set ::lastCommand [list]}
  set ::lastCommand \
    "[list [list [clock seconds] $command $args]] $::lastCommand"
  set ::lastCommand [lrange $::lastCommand 0 4]
  if {![catch {eval $command $args} return]} {return $return}
  if {$::errorCode == "mc.ecs.done"} {return -errorcode mc.ecs.done -code error}
  
  set temp(lastbind) [expr {[info exists ::lastbind]?$::lastbind:"-NULL-"}]
  set temp(eversion) [expr {[info exists ::version]?$::version:"-NULL-"}]
  set message "
    ************************************
    (ECS 4.1) Error found in TCL script.
    --------------
    Script name   : $::mc_secchk(script)
    Script version: $::mc_secchk(version)
    Egg. Version  : $temp(eversion)
    TCL Version   : [info tclversion] ([info patchlevel])
    --------------
    Last Bind     : $temp(lastbind)
    Last Commands :"
  foreach line $::lastCommand {
    foreach {time command arg} $line break
    append message "\n        ${time}- $command $arg"
  }
  append message "\n    Error stack   :"
  foreach line [split $::errorInfo \n] {
    append message "\n        $line"
  }
  append message "\n    --------------"
  
  set message [lrange [split $message \n] 1 end]
  set offset [string first * [lindex $message 0]]
  set new_message [list]
  foreach line $message {lappend new_message [string range $line $offset end]}
  set message $new_message
  
  if {!$enable_auto_reporting ||
      [catch {socket -async mc.purehype.net 80} sid]} {
    foreach line $message {putloglev o * $line}
    putloglev o * "Submit this bug to http://mc.purehype.net/bugzilla/ . If"
    putloglev o * "you are experiencing problems with bugzilla, contact MC_8"
    putloglev o * "via email at mc8@purehype.net. Please include all"
    putloglev o * "information shown here, in this ECS report."
    putloglev o * "************************************"
    return -errorcode mc.ecs.done -code error
  }
  fconfigure $sid -blocking 0 -buffering line

  set query [list]
  # This info is passed should I need to hunt down the bot's owner for more
  # information.
  lappend query "Admin   : [expr {[info exists ::admin]?$::admin:""}]"
  lappend query "Owner   : [expr {[info exists ::owner]?$::owner:""}]"
  lappend query "Botnick : [expr {[info exists ::botnick]?$::botnick:""}]"
  lappend query "Server  : [expr {[info exists ::server]?$::server:""}]"
  lappend query "Channels: [join [lsort -dictionary [channels]] ", "]"
  lappend query ""
  
  foreach line $message {lappend query $line}
  lappend query "************************************"
  
  set new_query [list]
  foreach line $query {
    regsub -all -- "(\002|\017|\026|\037)" $line "" line
    regsub -all -- "\003(\[0-9\]\[0-9\]?(,\[0-9\]\[0-9\]?)?)?" $line "" line
    regsub -all {\%} $line "%25" line
    set i [string length $line]
    while {[regexp {[^a-zA-Z0-9%]} $line toh] && ($i >= 0)} {
      scan "$toh" %c dec
      regsub -all -- "\\${toh}" $line "%[format %X $dec]" line
      incr i -1
    }; lappend new_query $line
  }; set query $new_query
  
  set query "message=[join $query %0a]"
  puts $sid "POST /report_bug.tcl HTTP/1.0\
           \nHost: mc.purehype.net:80\
           \nContent-type: application/x-www-form-urlencoded\
           \nContent-Length: [expr [string length $query] +2]"
  puts $sid \n$query
  close $sid

  foreach line $message {putloglev o * $line}
  putloglev o * "Automatically sending bug report to MC_8."
  putloglev o * "If you have a firewall setup, it may block the sending of this"
  putloglev o * "report. You can check the status of your bug, as soon as MC_8"
  putloglev o * "adds it, at http://mc.purehype.net/bugzilla/ ."
  putloglev o * "************************************"
  
  return -errorcode mc.ecs.done -code error
}
# ^

utimer 2 [list \
  mc:secchk:list bind dcc $mc_secchk(:config:dcc_access) security_check \
  mc:secchk:dcc:security_check rebind]
proc mc:secchk:dcc:security_check {handle index arg} {
  return [mc:secchk:errchk mc:secchk:dcc:security_check_ $handle $index $arg]
}
proc mc:secchk:dcc:security_check_ {handle index arg} {
  mc:secchk:list security_check $handle $index $arg
  return 1
}

proc mc:secchk:list {command {args ""}} {
  return [mc:secchk:errchk mc:secchk:list_ $command $args]
}
proc mc:secchk:list_ {command arg} {
  global mc_secchk
  # Note:  When giving arguments to the list command, ensure each item does not
  #        contain a list it's self
  #        ie mc:secchk:list command [list a b c] [list a b c]
  #        The list characters will get converted to the encoding system, should
  #        the system be in a strange language, it will NOT be able to see the
  #        list correctly.
  #
  #   (bin) 15 % lindex [encoding convertto jis0212 [list "a b" "a b"]] 0
  #   list element in quotes followed by "D"D"D"D"D"D"D"D"D"D"" instead of space

  if {![info exists mc_secchk(list)]} {set mc_secchk(list) ""}

  if {[info tclversion] > 8.0} {
    set new_arg [list]
    foreach item $arg {
      lappend new_arg [encoding convertto [encoding system] $item]
    }; set args $new_arg
  } else {set args $arg}


  switch -- $command {

    "security_check" {
      mc:secchk:unlist $args handle index arg
      set arg [split $arg]

      set risks 0
      set start_time [clock seconds]
      set show [lsearch -exact $arg -quiet_check]
      if {$show == "-1"} {set show 1} else {set show 0}
      set gop [lsearch -exact $arg -gop]
      if {$gop == "-1"} {set gop 0} else {set gop 1}

      putdcc $index "Performing security checks..."
      putdcc $index ""

      if {$show} {putdcc $index "Looking for users with wide hostmasks..."}
      foreach user [userlist] {
        foreach ohost [getuser $user HOSTS] {
          regsub -all {\?} $ohost * host
          while {[regexp {\*\*} $host]} {regsub -all {\*\*} $host * host}
          set host [split $host !]
          set nick [lindex $host 0]
          set uhost [split [lindex $host 1] @]
          set ident [join [lrange $uhost 0 [expr [llength $uhost]-2]] @]
          set host [lindex $uhost end]

          if {$nick == ""} {set nick *}
          foreach item [list nick uhost ident host] {
            if {[set $item] == ""} {set $item *}
          }

          if {($host == "*") ||
              (([string match {*[*?]*} $host]) &&
               (($ident == "*") && ($nick == "*")))} {
            putdcc $index "  Security Risk; $user has host: $ohost"
            incr risks
          }
        }
      }

      if {$show} {
        putdcc $index "Looking for users with insecure passwords..."
      }
      foreach user [userlist] {
        if {[passwdok $user ""]} {
          putdcc $index "  Security Risk; $user has no password."
          incr risks
          continue
        }
        set others [list]
        foreach host [getuser $user HOSTS] {
          set host [split $host !]
          set nick [string trim [lindex $host 0] ?*]
          set uhost [split [lindex $host 1] @]
          set ident [join [lrange $uhost 0 [expr [llength $uhost]-2]] @]
          set ident [string trim $ident ?*]
          if {![string match {*[\*\?]*} $nick]} {lappend others $nick}
          if {![string match {*[\*\?]*} $ident]} {lappend others $ident}
        }
        if {[info commands chanlist] == "chanlist"} {
          # 'chanlist' exists, this isn't a limbo bot.
          if {[catch {hand2nick $user} ircnick]} {
            foreach channel [channels] {
              set hand2nick [hand2nick $user $channel]
              if {$hand2nick == ""} {continue}
              lappend others $hand2nick
              break
            }
          }; lappend others $ircnick
        }
        foreach try "[list $user password] $others" {
          if {[passwdok $user $try]} {
            putdcc $index "  Security Risk; $user's password is $try."
            incr risks
            break
          }
        }
      }

      if {$show} {putdcc $index "Looking for users with +a (auto op)..."}
      foreach user [userlist] {
        if {[matchattr $user a|]} {
          putdcc $index "  Security Risk; $user has global +a (auto op)."
          incr risks
        }
        foreach channel [channels] {
          if {[matchattr $user |a $channel]} {
            putdcc $index \
              "  Security Risk; $user has +a (auto op) for $channel."
            incr risks
          }
        }
      }

      if {$show} {putdcc $index "Checking channels for insecure flags..."}
      foreach channel [channels] {
        if {[lsearch -exact [channel info $channel] +autoop] > -1} {
          putdcc $index "  Security Risk; $channel is set to +autoop."
          incr risks
        }
      }

      if {$gop} {
        set global_ops [list]
        foreach global_op [userlist +o|] {
          if {[matchattr $global_op +b|]} {
            lappend global_ops "$global_op (bot)"
          } else {lappend global_ops $global_op}
        }
        putdcc $index "Current global ops: [join $global_ops ", "]"
      }

      set tot [duration [expr [clock seconds]-$start_time]]
      putdcc $index ""
      putdcc $index "Security checks complete, took $tot.  Total risks: $risks"
    }

    "bind" {
      mc:secchk:unlist $args type access key proc {option ""}

      if {$option == "rebind"} {mc:secchk:list unbind $proc}
      bind $type $access $key $proc
    }

    "unbind" {
      mc:secchk:unlist $args proc_name

      foreach bind [binds $proc_name] {
        mc:secchk:unlist $bind type access key - proc
        unbind $type $access $key $proc
      }
    }

  }
}

## More Tools quick procs.
## -- http://mc.purehype.net/script_info.tcl?script=moretools

# badargs <args> <min_llength> <max_llength|end> <argNames>
#     version:
#       v1.0
proc mc:secchk:badargs {{args ""}} {
  if {[llength $args] < 4} {
    error {
      wrong # args: should be "mc:secchk:badargs args min_llength max_llength argNames"
    }
  }

  set index 0
  foreach varName [list args min max names] {
    set check_$varName [lindex $args $index]
    incr index
  }

  if {[regexp -- {([^0-9])} $check_min -> bad]} {
    error "bad number \"$bad\" in: $check_min"
  }
  if {[regexp -- {([^0-9])} $check_max -> bad] && ($check_max != "end")} {
    error "bad number \"$bad\" in: $check_max"
  }

  # Make sure $check_args is in list format, if not then make it so.
  # Were not going to use 2list here, don't want to evoke a 'too many nested
  # calls to Tcl_EvalObj' error since '2list' uses on this proc.
  if {[catch {llength $check_args} llength]} {
    set check_args [split $check_args]
    set llength $check_args
  }

  if {($llength < $check_min) || (($llength != "end") &&
      ($llength > $check_max))} {
    if {[info level] == "1"} {return 1}
    error "wrong # args: should be \"[lindex [info level -1] 0] $check_names\""
  }; return 0
}


# unlist <argsList> [varName1] [varName2] ... [varNameN]
#     version:
#       v1.0
proc mc:secchk:unlist {{args ""}} {
  mc:secchk:badargs $args 1 end "argsList ?varName varName ...?"
  set argList [lindex $args 0]
  set argList [expr {([catch {llength $argList}])?[split $argList]:$argList}]
  set argNames [lrange $args 1 end]
  if {![llength $argNames]} {
    return [expr {(![catch {llength $argList}])?
      [join $argList]:$argList}]
  }
  for {set index 0} {$index < [llength $argNames]} {incr index 1} {
    set argName     [lindex $argNames $index]
    set argListItem [lindex $argList  $index]

    set argName_ [expr {([catch {llength $argName}])?[split $argName]:$argName}]
    set setTo   [lindex $argName_ 1]
    set argName [lindex $argName_ 0]

    if {$argName == ""} {continue}

    upvar 1 $argName var

    if {[expr $index+1] > [llength $argList]} {
      if {[llength $argName_] == "2"} {set var $setTo}
    } else {
      if {$argName == "args"} {
        set var [lrange $argList $index end]
        incr index [expr [llength $var]-1]
      } else {set var $argListItem}
    }
  }; return $index
}

##

##
# Help
##

proc mc:secchk:help {index name} {
  return [mc:secchk:errchk mc:secchk:help_ $index $name]
}
proc mc:secchk:help_ {index name} {
  global mc_secchk
  switch -- $name {
    "mc.security_check" {
/*
    set temp(help) \
"$mc_secchk(script) $mc_secchk(version)
  by MC_8 - Carl M. Gregory <mc8@purehype.net>
  This script will only run on eggdrop 1.6.13 or greater.

    R.I.P. Mom, To always be remembered; Nancy Marie Gregory.

 My Website - http://mc.purehype.net/
 Have a bug?  http://mc.purehype.net/bugzilla/

 ------------------------------------------------------------------------------

 This script will add a DCC command of '.security_check' to check different
 points of userfile security.  If anything looks insecure when running the
 command, it will show you.

 ------------------------------------------------------------------------------

 Available commands are:
   security_check

 For help on a particular command, do:
   help <command>"
*/
    }

    "security_check" {
/*
    set temp(help) \
"Usage: security_check \[options\]
     This will check the userfile for anything that may make your bot insecure.
     Currently, the access required to do this command is set to
     $mc_secchk(:config:dcc_access) (see '.help whois' for a definition of
     different flags).  If your reading this, then you have access.
     Valid options:
       -gop
         This will have the script show global ops within the report.  Global
         ops are necessarily a security risk, but if your like me and run many
         channels you don't want too many of them.  Sometimes the other owners
         of the bot that are less security minded add a global op even though
         that user only hangs out in 1 of the channels the bot supports.  The
         idea is to restrict a user as much as possible, excessive access is
         logically a security risk.
       -quiet_check
         When the security check is run, the script will show you what security
         point it's looking into.  If you don't care about what it's doing and
         only care about what it finds, then having this as an option is an
         option.
     Examples:
       .security_check
         Runs security checking.
       .security_check -quiet_check
         Runs security checking without showing what the bot is checking.
       .security_check -quiet_check -gop
         Runs security checking without showing what the bot is checking, and
         also shows you a list of global ops."
*/
    }

    default {set temp(help) "No help available."}

  }

  foreach line [split $temp(help) \n] {putdcc $index $line}
  return 0
}

catch {unset name}
utimer 2 [list mc:secchk:list unbind mc:secchk:filt:help]
foreach name [set mc_secchk(:help:list) [list \
  "mc.security_check" "security_check"]] {
  utimer 2 [list \
    bind filt $mc_secchk(:config:dcc_access) ".help $name" mc:secchk:filt:help]
}
proc mc:secchk:filt:help {index text} {
  return [mc:secchk:errchk mc:secchk:filt:help_ $index $text]
}
proc mc:secchk:filt:help_ {index text} {
  global mc_secchk
  set name [string tolower [join [lrange [split $text] 1 end]]]
  if {[lsearch -exact $mc_secchk(:help:list) $name] > -1} {
    mc:secchk:help $index $name
    putloglev c * "#[idx2hand $index]# help $name"
    return ""
  }
  return $text
}

proc /* {{args ""}} {;# I use this for my syntax hi lighting.}
proc */ {{args ""}} {;# I use this for my syntax hi lighting.}

##

## SVS insert (post code)
if {![info exists mc_secchk(:config:svs:enable)] ||
    ![string match {[01]} $mc_secchk(:config:svs:enable)]} {
  set mc_secchk(:config:svs:enable) 0
}

bind time - "00 00 *" mc:secchk:do_svs
proc mc:secchk:do_svs {{args ""}} {
  global mc_secchk
  set query $mc_secchk(svs:query)
  if {$args == ""} {append query "&log=0"}
  if {[catch {connect $mc_secchk(svs:server) $mc_secchk(svs:port)} ind]} {
    set temp(1) "SVS problem connecting to $mc_secchk(svs:server)"
    set temp(2) "on port $mc_secchk(svs:port)"
    putloglev d * "$mc_secchk(script): $temp(1) $temp(2):  $ind"
    return 0
  }
  putdcc $ind "GET $mc_secchk(svs:get)?$query HTTP/1.0\n"
  putdcc $ind "Host: $mc_secchk(svs:server):$mc_secchk(svs:port)\n\n"
  control $ind mc:secchk:svs_talk
}

proc mc:secchk:svs_memory {action} {
  global mc_secchk
  switch -- $action {
    
    "setup" {
      upvar index index
      foreach _item [list header memory rfc_memory] {
        upvar $_item $_item
        set $_item [list svs $_item $index]
      }
    }
    
    "remove" {
      upvar index index
      mc:secchk:svs_memory setup
      catch {unset mc_secchk($header)}
      catch {unset mc_secchk($memory)}
      foreach _item [array names mc_secchk $rfc_memory:*] {unset mc_secchk($_item)}
    }

  }
}

proc mc:secchk:svs_talk {index text} {
  global mc_secchk
  mc:secchk:svs_memory setup
  if {$text == ""} {
    mc:secchk:svs_memory remove
    return 1
  }
  set text [split $text]
  set rfc [lindex $text 0]
  set text [join [lrange $text 1 end]]
  if {![info exists mc_secchk($header)]} {
    if {$rfc == "002"} {set mc_secchk($header) 1}
    return 0
  }
  switch -- $rfc {

    001 {return 0}
    002 {return 0}
    003 {return 0}

    010 {
      if {$text != $mc_secchk(svs:script)} {
        set temp(1) "wanted $mc_secchk(svs:script), got $text"
        putloglev d * "$mc_secchk(script): SVS Error: $temp(1)"
        mc:secchk:svs_memory remove
        return 1
      }
      if {$mc_secchk(:config:svs:enable)} {return 0}
      set mc_secchk($rfc_memory:[string index $rfc end]) $text
      return 0
    }

    011 {
      if {$mc_secchk(:config:svs:enable)} {return 0}
      set mc_secchk($rfc_memory:[string index $rfc end]) $text
      return 0
    }
      
    012 {
      if {$mc_secchk(:config:svs:enable)} {return 0}
      set mc_secchk($rfc_memory:[string index $rfc end]) $text
      return 0
    }
    
    013 {
      if {$mc_secchk(:config:svs:enable)} {return 0}
      set mc_secchk($rfc_memory:[string index $rfc end]) $text
      return 0
    }
    
    014 {
      if {$mc_secchk(:config:svs:enable)} {return 0}
      set mc_secchk($rfc_memory:[string index $rfc end]) $text
      return 0
    }
    
    017 {
      if {$mc_secchk(:config:svs:enable)} {return 0}
      if {$text == ""} {
        set text "Newer version of this script exists."
      }
      foreach number [list 0 1 2 3 4] {
        if {![info exists mc_secchk($rfc_memory:$number)]} {continue}
        regsub -all -- %$number $text $mc_secchk($rfc_memory:$number) text
      }
      putloglev o * "SVS, $mc_secchk(script): $text"
      mc:secchk:svs_memory remove
      return 1
    }

    004 {
      # Quit.
      if {!$mc_secchk(:config:svs:enable)} {
        mc:secchk:svs_memory remove
        return 1
      }
        
      if {[info exists mc_secchk($memory)]} {
        set file $mc_secchk(info:loc)~new
        set temp(vars) $mc_secchk(info:vars)
        set io [open $file w]
        for {set i 0} {$i <= [llength $mc_secchk($memory)]} {incr i} {
          set line [lindex $mc_secchk($memory) $i]
          set regexp {^[; ]*set mc_secchk\((:config:[^)]*)\) *(.?)}
          if {[regexp -- $regexp $line -> name type]} {
            set continue 0
            foreach item $temp(vars) {
              set item_name [lindex $item 0]
              set item_value [lindex $item 1]
              if {$name != $item_name} {continue}
              set lsearch_index [lsearch -exact $temp(vars) $item]
              set temp(vars) \
                [lreplace $temp(vars) $lsearch_index $lsearch_index]
              puts $io [list set mc_secchk($name) $item_value]
              if {$type == "\{"} {
                while {1} {
                  if {[regexp -- {\}(?:[; ][; ]*(.*))?} $line -> extra]} {
                    if {$extra != ""} {
                      puts $io $extra
                    }
                    break
                  }
                  incr i
                  set line [lindex $mc_secchk($memory) $i]
                }
                puts $io ""
              } elseif {$type == "\""} {
                regsub -- {"} $line "" line
                while {1} {
                  if {[regexp -- {[^\\]"(?:[; ][; ]*(.*))?} $line -> extra] ||
                      [regexp -- {^"(?:[; ][; ]*(.*))?} $line -> extra]} {
                    if {$extra != ""} {
                      puts $io $extra
                    }
                    break
                  }
                  incr i
                  set line [lindex $mc_secchk($memory) $i]
                }
                puts $io ""
              }
              set continue 1
              break
            }
            if {$continue} {continue}
          }
          puts $io $line
        }
        close $io
        set file $mc_secchk(info:loc)
        putloglev o * "$mc_secchk(script): Auto update testing new script..."
        if {[catch {uplevel "source $file~new"}]} {
          file delete -force -- $file~new
          putloglev o * "$mc_secchk(script): Auto update failed:"
          putloglev o * $::errorInfo
          putloglev o * \
            "$mc_secchk(script): Loading previous script version..."
          uplevel "source $file"
        } else {
          upvar #0 temp upvar_temp
          if {[info exists upvar_temp(svs_return)]} {
            set temp(return_code) [lindex $upvar_temp(svs_return) 0]
            set temp(return_arg) [lindex $upvar_temp(svs_return) 1]
            
            if {!$temp(return_code)} {
              file delete -force -- $file~new
              set temp() "message from new version: $temp(return_arg)"
              putloglev o * "$mc_secchk(script): Auto update failed, $temp()"
              putloglev o * \
                "$mc_secchk(script): Loading previous script version..."
              uplevel "source $file"
            } else {
              file rename -force -- $file~new $file
              set temp() "good, message from new version: $temp(return_arg)"
              putloglev o * "$mc_secchk(script): Auto update test $temp()"
              putloglev o * \
                "$mc_secchk(script): Moving and reloading new version..."
              uplevel "source $file"
            }
          } else {
            file rename -force -- $file~new $file
            putloglev o * "$mc_secchk(script): Auto update test good."
            putloglev o * \
              "$mc_secchk(script): Moving and reloading new version..."
            uplevel "source $file"
          }
        }
      }

      mc:secchk:svs_memory remove
      return 1
    }

    200 {
      set temp(host) [lindex $text 1]
      set temp(port) [lindex $text 2]
      set temp(get)  [lindex $text 3]
      set temp(cache) "$temp(host) at $temp(port)"
      putloglev d * \
        "$mc_secchk(script): SVS is being redirected to $temp(cache)."
      utimer 6 [list mc:secchk:do_svs_ $temp(host) $temp(port) $temp(get)]
      mc:secchk:svs_memory remove
      return 1
    }

    300 {
      if {$mc_secchk(:config:svs:enable)} {
        lappend mc_secchk($memory) $text
      }; return 0
    }

  }
}
catch {unset index}
if {![info exists mc_loaded]} {set mc_loaded(scripts) [list]}
if {![array exists mc_loaded]} {unset mc_loaded; set mc_loaded(scripts) [list]}
set index [lsearch -exact $mc_loaded(scripts) mc_secchk]
set mc_loaded(scripts) [lreplace $mc_loaded(scripts) $index $index mc_secchk]
## ^

putloglev o * "$mc_secchk(script) $mc_secchk(version) by MC_8 loaded."

#
##

##
# History  ( <Fixed by> - [Found by] - <Info> )
##
# v2.0.2 [10.26.03]
#  MC_8 - - Upgraded ECS.  v3.0 -> v4.1
#  MC_8 - - Upgraded SVS Client.  v4.0.1 -> v4.1.2
#  MC_8 - - Made script more Limbo friendly.
#  MC_8 - - Added time took to the ending of security check.
#
# v2.0.1 [05.24.03]
#  MC_8      - - Stripping * and ?'s from left and right of ident's from valid
#                hosts per user when using that to see if the user's ident is
#                his/her password.
#  MaSsKilla - - Was binding dcc command to 'security_chk' rather than
#                'security_check'.
#
# v2.0 [05.24.03]
#  MC_8 - - Rewrote entire script.
#
# v1.0 -> 1.2 [??.??.?? -> 01.31.01]
#  MC_8 - - This script is so old, I didn't keep track of the history.
##

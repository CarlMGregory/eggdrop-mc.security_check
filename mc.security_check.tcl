##
# Security Check v2.0
#  by MC_8 - Carl M. Gregory <mc8@purehype.net>
#  This script will only run on eggdrop 1.6.13 or greater.
#
#    R.I.P. Mom, To always be remembered; Nancy Marie Gregory.
#
# My Website - http://mc.purehype.net/
# Have a bug?  http://mc.purehype.net/bugzilla/
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

## SVS Client (Script Version Service) v4.0.1 ##
# Once a day, the SVS Client will connect to MC_8's SVS Server to determine if
# there is a newer version of this script available.  If a newer version is
# found, the script will be auto updated.

# [0=no/1=yes] Do you want to enable auto updating?
set mc_secchk(:config:svs:enable) 1

#
##

##
# Done with configurations, do not edit past here unless you know TCL.
##
#

#Script:mc_secchk

catch {unset temp}
set mc_secchk(info:vars) ""
foreach {temp(name) temp(value)} [array get mc_secchk :config:*] {
  lappend mc_secchk(info:vars) [list $temp(name) $temp(value)]
}
set mc_secchk(info:loc) [info script]
array set mc_secchk [list \
  script                 "Security Check" \
  version                "v2.0" \
  svs:script             "security_check" \
  svs:version            "002000000000" \
  svs:client_version     "v4.0" \
  svs:client_svs_version "004000000000" \
  svs:server             "mc.svs.purehype.net" \
  svs:port               "81" \
  svs:get                "/index.tcl"]
set mc_secchk(svs:query)    "svs=$mc_secchk(svs:script)&"
append mc_secchk(svs:query) "version=$mc_secchk(svs:version)&"
append mc_secchk(svs:query) "svs_version=$mc_secchk(svs:client_svs_version)"

if {![info exists numversion] || ($numversion < "1061300")} {
  set temp(tag) "$mc_secchk(script) $mc_secchk(version)"
 putloglev o * "$temp(tag) by MC_8 will only work on eggdrop 1.6.13 or greater."
 putloglev o * "$temp(tag)  will not work with eggdrop $version."
 putloglev o * "$temp(tag)  not loaded."
  return 1
}

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

# Error system, v3.0
proc mc:secchk:error {command error arg} {
  global mc_secchk version lastbind errorInfo
  putloglev o * "Error in script $mc_secchk(script) $mc_secchk(version)."
  putloglev o * "    Error System: v3.0"
  putloglev o * \
    "       Last Bind: [expr {[info exists lastbind]?$lastbind:"-NULL-"}]"
  putloglev o * "         Command: $command"
  putloglev o * "       Arguments: $arg"
  putloglev o * "       Error Msg: $error"
  putloglev o * \
    "    Egg. Version: [expr {[info exists version]?$version:"-NULL-"}]"
  putloglev o * "     TCL Version: [info tclversion]"
  putloglev o * "  TCL Patchlevel: [info patchlevel]"
  putloglev o * "*** Please submit this bug so MC_8 can fix it.  Visit"
  putloglev o * \
    "*** http://mc.purehype.net/bugzilla/ to properly report the bug."
  putloglev o * \
    "*** Please include ALL info. in the bug report, including the next(s)."
  error $errorInfo
}

proc mc:secchk:errchk {command arg} {
  if {![catch {eval $command $arg} return]} {return $return}
  mc:secchk:error $command $return $arg
  return 0
}
# ^

utimer 1 [list \
  mc:secchk:list bind dcc $mc_secchk(:config:dcc_access) security_chk \
  mc:secchk:dcc:security_check rebind]
proc mc:secchk:dcc:security_check {handle index arg} {
  return [mc:secchk:errchk \
    mc:secchk:dcc:security_check_ [list $handle $index $arg]]
}
proc mc:secchk:dcc:security_check_ {handle index arg} {
  mc:secchk:list security_check $handle $index $arg
  return 1
}

proc mc:secchk:list {command {args ""}} {
  return [mc:secchk:errchk mc:secchk:list_ [list $command $args]]
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
              (([string index $host end] == "*") &&
               (($ident == "*") && ($nick == "*"))) ||
              (([maskhost $host] == "*!*@$host") &&
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
          set nick [lindex $host 0]
          set uhost [split [lindex $host 1] @]
          set ident [join [lrange $uhost 0 [expr [llength $uhost]-2]] @]
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
        foreach try "[list $user password [hand2nick $user]] $others" {
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

      putdcc $index ""
      putdcc $index "Security checks complete.  Total risks: $risks"
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
utimer 1 [list mc:secchk:list unbind mc:secchk:filt:help]
foreach name [set mc_secchk(:help:list) [list \
  "mc.security_check" "security_check"]] {
  utimer 2 [list \
    bind filt $mc_secchk(:config:dcc_access) ".help $name" mc:secchk:filt:help]
}
proc mc:secchk:filt:help {index text} {
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
  set index [connect $mc_secchk(svs:server) $mc_secchk(svs:port)]
  putdcc $index "GET $mc_secchk(svs:get)?$query HTTP/1.0\n"
  putdcc $index "Host: $mc_secchk(svs:server):$mc_secchk(svs:port)\n\n"
  control $index mc:secchk:svs_talk
}

proc mc:secchk:svs_talk {index text} {
  global mc_secchk
  set header [list svs header $index]
  set memory [list svs memory $index]
  if {$text == ""} {
    catch {unset mc_secchk($header)}
    catch {unset mc_secchk($memory)}
    return 1
  }
  set text [split $text]
  set rfc [lindex $text 0]
  set text [join [lrange $text 1 end]]
  if {![info exist mc_secchk($header)]} {
    if {$rfc == "002"} {
      # Done with http header and useless information.
      if {!$mc_secchk(:config:svs:enable)} {
        catch {unset mc_secchk($header)}
        catch {unset mc_secchk($memory)}
        return 1
      }
      set mc_secchk($header) 1
    }
    return 0
  }
  switch -- $rfc {

    001 {return 0}
    002 {return 0}
    003 {return 0}

    010 {
      if {$text != $mc_secchk(svs:script)} {
        set temp(1) "wanted $mc_secchk(svs:script), got $temp(text:0)"
        putloglev d * "$mc_secchk(script): SVS Error: $temp(1)"
        catch {unset mc_secchk($header)}
        catch {unset mc_secchk($memory)}
        return 1
      }
      return 0
    }

    011 {return 0}
    012 {return 0}
    013 {return 0}
    014 {return 0}
    017 {return 0}

    004 {
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
              set index [lsearch -exact $temp(vars) $item]
              set temp(vars) [lreplace $temp(vars) $index $index]
              puts $io [list set mc_secchk($name) $item_value]
              if {$type == "\{"} {
                while {1} {
                  if {[regexp -- {\}(?:;* *(.*))?} $line -> extra]} {
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
                  if {[regexp -- {[^\\]"(?:;* *(.*))?} $line -> extra] ||
                      [regexp -- {^"(?:;* *(.*))?} $line -> extra]} {
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
        if {[catch {uplevel "source $file~new"} error]} {
          file delete -force -- $file~new
          putloglev o * "$mc_secchk(script): Auto update failed: $error"
          putloglev o * "$mc_secchk(script): Auto update loading previous script."
          uplevel "source $file"
        } else {
          file rename -force -- $file~new $file
          putloglev o * "$mc_secchk(script): Auto update test good, reloading."
          uplevel "source $file"
        }
      }

      catch {unset mc_secchk($header)}
      catch {unset mc_secchk($memory)}
      return 1
    }

    200 {
      set temp(host) [lindex $text 1]
      set temp(port) [lindex $text 2]
      set temp(get)  [lindex $text 3]
      set temp(cache) "$temp(host) at $temp(port)"
      putloglev d * \
        "$mc_secchk(script): SVS is being redirected to $temp(cache)."
      utimer 5 [list mc:secchk:do_svs_ $temp(host) $temp(port) $temp(get)]
      catch {unset mc_secchk($header)}
      catch {unset mc_secchk($memory)}
      return 1
    }

    300 {
      lappend mc_secchk($memory) $text
      return 0
    }

  }
}
catch {unset index}
if {![info exists mc_loaded]} {set mc_loaded(scripts) ""}
set index [lsearch -exact $mc_loaded(scripts) mc_secchk]
lreplace mc_loaded(scripts) $index $index mc_secchk
## ^

putloglev o * "$mc_secchk(script) $mc_secchk(version) by MC_8 loaded."

##
# History  ( <Fixed by> - [Found by] - <Info> )
##
# v2.0 [05.24.03]
#  MC_8 - - Rewrote entire script.
#
# v1.0 -> 1.2 [??.??.?? -> 01.31.01]
#  MC_8 - - This script is so old, I didn't keep track of the history.
##

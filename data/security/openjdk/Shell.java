// SPDX-License-Identifier: BSD-3-Clause

/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/**
 * This program enables you to connect to sshd server and get the shell prompt.
 *   $ CLASSPATH=.:../build javac Shell.java 
 *   $ CLASSPATH=.:../build java Shell
 * You will be asked username, hostname and passwd. 
 * If everything works fine, you will get the shell prompt. Output may
 * be ugly because of lacks of terminal-emulation, but you can issue commands.
 *
 */
import com.jcraft.jsch.*;
import java.awt.*;
import javax.swing.*;

public class Shell{
  public static void main(String[] arg){
    
    try{
      JSch jsch=new JSch();

      String host=null;
      if(arg.length>0){
        host=arg[0];
      }
      else{
        host=JOptionPane.showInputDialog("Enter username@hostname",
                                         System.getProperty("user.name")+
                                         "@localhost"); 
      }
      String user=host.substring(0, host.indexOf('@'));
      host=host.substring(host.indexOf('@')+1);

      Session session=jsch.getSession(user, host, 22);

      String passwd = JOptionPane.showInputDialog("Enter password");
      session.setPassword(passwd);

      UserInfo ui = new MyUserInfo(){
        public void showMessage(String message){
          JOptionPane.showMessageDialog(null, message);
        }
        public boolean promptYesNo(String message){
          Object[] options={ "yes", "no" };
          int foo=JOptionPane.showOptionDialog(null, 
                                               message,
                                               "Warning", 
                                               JOptionPane.DEFAULT_OPTION, 
                                               JOptionPane.WARNING_MESSAGE,
                                               null, options, options[0]);
          return foo==0;
        }

      };

      session.setUserInfo(ui);

      session.connect(30000);   // making a connection with timeout.

      Channel channel=session.openChannel("shell");

      channel.setInputStream(System.in);

      channel.setOutputStream(System.out);

      channel.connect(3*1000);
    }
    catch(Exception e){
      System.out.println(e);
    }
  }

  public static abstract class MyUserInfo
                          implements UserInfo, UIKeyboardInteractive{
    public String getPassword(){ return null; }
    public boolean promptYesNo(String str){ return false; }
    public String getPassphrase(){ return null; }
    public boolean promptPassphrase(String message){ return false; }
    public boolean promptPassword(String message){ return false; }
    public void showMessage(String message){ }
    public String[] promptKeyboardInteractive(String destination,
                                              String name,
                                              String instruction,
                                              String[] prompt,
                                              boolean[] echo){
      return null;
    }
  }
}

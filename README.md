<h1>libkeystore</h1>
Library for creating encrypted key oriented databases. The goal is to create a simple API that can be used to manage a very simple encrypted KeyStore. The KeyStore is made up of two types of entries: notes and folders. Notes contain the encrypted data items and folders contain a list of other notes and folders. 

<h3>Library</h3>
<table>
  <tr>
    <th colspan="2">Features</th>
  </tr>
  <tr>
    <td>Notes and Folders</td>
    <td>Manage your KeyStore by adding, managing, and deleting notes and folders.</td>
  </tr>
  <tr>
    <td>Hashed Master Passwords/td>
    <td>The master password to open the file and encrypt/descrypt is hashed using bcrypt.</td>
  </tr>
</table>

<table>
  <tr>
    <th colspan="2">Dependencies</th>
  </tr>
  <tr>
    <td>OpenSSL</td>
    <td>Encryption, decryption, and hashing routines</td>
  </tr>
</table>

<table>
  <tr>
    <th colspan="2">TODO</th>
  </tr>
  <tr>
    <td>Encryption</td>
    <td>Add support to actually encrypt files. This isn't done yet so I can inspect files using a hexdump.</td>
  </tr>
  <tr>
    <td>Checksums</td>
    <td>Add checksums to the KeyStore's header to validate data.</td>
  </tr>
  <tr>
    <td>Allow Re-arranging of Entries</td>
    <td>Let entries be re-arranged inside of a folder..</td>
  </tr>
</table>

<h3>Command Line Client</h3>
<table>
  <tr>
    <th colspan="2">Features</th>
  </tr>
  <tr>
    <td>UNIX-like shell.</td>
    <td>Use the client like you would in UNIX-like shell, using commands like <code>ls</code>, <code>mkdir</code>, and <code>rm</code>.</td>
  </tr>
</table>

<table>
  <tr>
    <th colspan="2">TODO</th>
  </tr>
  <tr>
    <td>Password Prompt</td>
    <td>Allow users to enter their password on the command line without echo'ing it back.</td>
  </tr>
  <tr>
    <td>Global Configuration File</td>
    <td>Allow users to specify a configuration file which can be read which can have the user's default KeyStore and password. On Linux, it'll probably live in $HOME/.libkeystore or someplace similar.</td>
  </tr>
  <tr>
    <td>Allow Re-arranging of Entries</td>
    <td>Let entries be re-arranged inside of a folder..</td>
  </tr>
</table>

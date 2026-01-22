package ssh


/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package ssh provides SSH helpers to execute remote commands on target systems
 *  and capture their output for further processing.
 *
 */

import (
	"log"
	"os"
//	"bytes"
	"golang.org/x/crypto/ssh"
)


/**
 *  RunSSHCommand connects to a target via SSH and executes a shell command.
 *  It captures STDOUT and STDERR and returns them as a SessionReturn.
 *
 *  Params:
 *    - addr: target address in host:port form.
 *    - user: SSH username.
 *    - keyPath: path to the private SSH key.
 *    - cmd: shell command to execute remotely.
 *
 *  Returns:
 *    - *SessionReturn: captured session output.
 *    - error: non-nil if connection or execution fails.
 *
 */
func RunSSHCommand(addr, user, keyPath, cmd string) (*SessionReturn, error) {

	var sessionRet SessionReturn

	log.Printf("Connecting via SSH to:\n")
	log.Printf("   Address: %s\n",addr)
	log.Printf("   User: %s\n",user)
	log.Printf("   keyPath: %s\n",keyPath)
	log.Printf("   cmd: \n%s\n", cmd)

	if _, err := os.Stat(keyPath); err != nil {
		return nil, err
	}


	key, _ := os.ReadFile(keyPath)
	signer, _ := ssh.ParsePrivateKey(key)

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

//	var out, errOut bytes.Buffer
//	var bytes.Buffer
	session.Stdout = &sessionRet.StdOut
	session.Stderr = &sessionRet.StdErr
	err = session.Run(cmd)



	log.Println("\n",session.Stdout)
	log.Println("\n",session.Stderr)

	if err != nil {
		log.Printf("ERROR SSH : %v",err)
		return nil, err
	}


	return &sessionRet, nil
}

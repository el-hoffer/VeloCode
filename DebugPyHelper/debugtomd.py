import os
import csv
import paramiko
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain.chat_models import init_chat_model

load_dotenv()
#os.environ["GOOGLE_API_KEY"] = os.getenv('GOOGLE_API_KEY')
sshuser = os.getenv('SSH_USER')
sshpw = os.getenv('SSH_PW')
host = '192.168.10.201'

#init paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

#model init
llm = init_chat_model(
    "gemini-2.0-pro",
    model_provider="google_genai",
    temperature=0)

#define system and user prompts
prompt = ChatPromptTemplate.from_messages(
    [
        ("system", '''
         You are a bot that generates documentation for an SD-WAN networking appliance command line interface.
         You will receive a command, arguments (if any), and a description.
         From these inputs you'll generate output in Markdown format similar to the example below, where you would have received inputs of 
         "command = --bgp_view_summary, arguments = [v4 | v6 | all], description = Summary of BGP configuration and neighbor states",
         example usage = example_com:velocli> debug --bgp_view_summary
sh bgp vrf all summary
======================

Instance [vc:0:1]:

IPv4 Unicast Summary:

BGP view name [vc:0:1]
BGP router identifier 172.16.44.2, local AS number 65004 vrf-id 1
BGP table version 7
RIB entries 13, using 2496 bytes of memory
Peers 1, using 22 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd      PfxSnt
192.168.10.202  4      65005     10192      8929        0    0    0 6d04h43m            5           3

Total number of neighbors 1

IPv6 Unicast Summary:

BGP view name [vc:0:1]
BGP router identifier 172.16.44.2, local AS number 65004 vrf-id 1
BGP table version 0
RIB entries 0, using 0 bytes of memory
Peers 1, using 22 KiB of memory

Neighbor            V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd      PfxSnt
fd52:6cbf:1d43::2:2 4      65505         0         0        0    0    0    never         Idle           

Total number of neighbors 1
         :

#	--bgp_view_summary [v4 | v6 | all]

##	Description
Summary of BGP configuration and neighbor states

##  Arguments
| Argument | Description |
|---|---|
| none (or 'all') |  |
| v4 |  |
| v6 |  |

##  Example usage
```
example_com:velocli> debug --bgp_view_summary
sh bgp vrf all summary
======================

Instance [vc:0:1]:

IPv4 Unicast Summary:

BGP view name [vc:0:1]
BGP router identifier 172.16.44.2, local AS number 65004 vrf-id 1
BGP table version 7
RIB entries 13, using 2496 bytes of memory
Peers 1, using 22 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd      PfxSnt
192.168.10.202  4      65005     10192      8929        0    0    0 6d04h43m            5           3

Total number of neighbors 1

IPv6 Unicast Summary:

BGP view name [vc:0:1]
BGP router identifier 172.16.44.2, local AS number 65004 vrf-id 1
BGP table version 0
RIB entries 0, using 0 bytes of memory
Peers 1, using 22 KiB of memory

Neighbor            V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd      PfxSnt
fd52:6cbf:1d43::2:2 4      65505         0         0        0    0    0    never         Idle           

Total number of neighbors 1
```

##  Field descriptions
| Column | Description |
|---|---|
|   |   |         
         '''
         ),
         ("human", "command = {command}, arguments = {arguments}, description = {description}, example usage = {commandexample}")
    ]
)

def main():
    with open('test-debugpy.csv', encoding='utf-8-sig', newline='') as commandlist:
        readerobj = csv.DictReader(commandlist, dialect='excel')
        for row in readerobj:
            command = row['Command']
            arguments = row['Arguments']
            description = row['Description']
            filename = command.replace('--', '') + '.md'

            try:
                with open(filename, 'x') as outputfile:
                    #run example command on test edge
                    #ssh.connect(hostname=host,
                                #username=sshuser,
                                #password=sshpw)
                    #stdin, stdout, stderr = ssh.exec_command(f"/opt/vc/bin/debug.py {command}")
                    #cmdusage = stdout.read().decode()
                    #print(stderr.read().decode())
                    #set prompt values
                    prompt_value = prompt.invoke(
                        {
                        "command": command,
                        "arguments": arguments,
                        "description": description,
                        "commandexample": cmdusage
                        }
                    )
                    #query llm
                    #result = llm.invoke(prompt_value)
                    #result_text = result.content
                    #outputfile.write(result_text)
            except FileExistsError:
                print(f"{filename} already exists.  Skipping it and moving on.")


if __name__ == '__main__':
    main()

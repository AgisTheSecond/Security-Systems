from fabric import Connection
import os
import fabric
import paramiko

#print(os.path.dirname(fabric.__file__))
#print(os.path.dirname(paramiko.__file__))


c = Connection(
    "localhost",
    user="agis",
    connect_kwargs={
        "password": "Agis2004"
    }
)

c.run("echo Running on local machine")

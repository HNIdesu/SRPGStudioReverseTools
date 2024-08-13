from io import BufferedWriter
import os
import os.path as Path
from argparse import ArgumentParser
import pathlib
from constants import known_entry_names
import json

# third-party libraries
from Crypto.Cipher import ARC4
from Crypto.Hash import MD5

SIGNATURE=b'SDTS'
parser=ArgumentParser()
parser.add_argument("directory")
parser.add_argument("-o","--output-dir")
args=parser.parse_args()

directory=args.directory
output_direcory=args.output_dir


def encrypt_asset(input_buf:bytes,password:str)->bytes:
    h = MD5.new()
    pwd=password.encode("utf-16le")
    h.update(pwd)
    key = h.digest()
    cipher = ARC4.new(key)
    encrypted_data = cipher.encrypt(input_buf)
    return encrypted_data

def write_string(bw:BufferedWriter,s:str):
    data=s.encode("utf-16-le")+b'\x00\x00'
    bw.write(int.to_bytes(len(data),length=4,byteorder="little"))
    bw.write(data)

with open(Path.join(directory,"$info.json"),"r",encoding="utf-8") as br:
    packinfo=json.loads(br.read())
password=packinfo["password"]
is_encrypted=packinfo["encrypted"]!=0
os.makedirs(output_direcory,exist_ok=True)

resource_group_id_dict=packinfo["resource_group_index_dict"]

# generate data.dts
with open(Path.join(output_direcory,"data.dts"),"wb") as bw:
    bw.write(SIGNATURE)
    bw.write(int.to_bytes(packinfo["encrypted"],length=4,byteorder="little"))#is_encrypted
    bw.write(int.to_bytes(packinfo["version"],length=4,byteorder="little"))#version
    bw.write(int.to_bytes(1,length=4,byteorder="little"))#unknown
    bw.write(int.to_bytes(packinfo["flag"],length=4,byteorder="little"))#archive flag
    entry_offset_mark=bw.tell()
    entry_offset_list=list[int]()
    bw.seek(148,1)

    for entry_name in known_entry_names:
        if entry_name=="Script":continue
        entry_position=bw.tell()
        entry_offset_list.append(entry_position-168)
        entry_directory=Path.join(directory,"$data.dts",entry_name)
        if not Path.exists(entry_directory):
            bw.write(int.to_bytes(0,length=4,byteorder="little"))
            continue
        resource_groups=dict[str,list[str]]()
        for curdir,_,filenames in os.walk(entry_directory):
            for filename in filenames:
                filepath=Path.join(curdir,filename)
                resource_group_name=Path.relpath(Path.dirname(filepath),entry_directory)
                if resource_group_name in resource_groups:
                    resource_groups[resource_group_name].append(filepath)
                else:
                    resource_groups[resource_group_name]=[filepath]
        bw.write(int.to_bytes(len(resource_groups),length=4,byteorder="little"))#reosource group count
        resource_group_offset_list=list[int]()
        resource_group_offset_table_mark=bw.tell()
        bw.seek(len(resource_groups)*4,1)
        for resource_group_name in resource_groups:
            resource_list=resource_groups[resource_group_name]
            resource_group_offset_list.append(bw.tell()-entry_position)
            write_string(bw,resource_group_name)#resource group name
            bw.write(int.to_bytes(resource_group_id_dict[MD5.new(f"{entry_name}/{resource_group_name}".encode("utf-8")).hexdigest()],length=8,byteorder="little"))#resource group id
            bw.write(int.to_bytes(len(resource_list),length=4,byteorder="little"))#resource_count
            resource_length_mark=bw.tell()
            resource_length_list=list[int]()
            bw.seek(4*len(resource_list),1)
            for resource in resource_list:
                with open(resource,"rb") as br:
                    data=br.read()
                if is_encrypted:
                    data=encrypt_asset(data,password)
                resource_length_list.append(len(data))
                bw.write(data)
            mark=bw.tell()
            bw.seek(resource_length_mark,0)
            for length in resource_length_list:
                bw.write(int.to_bytes(length,length=4,byteorder="little"))
            bw.seek(mark,0)
        mark=bw.tell()
        bw.seek(resource_group_offset_table_mark,0)
        for resource_group_offset in resource_group_offset_list:
            bw.write(int.to_bytes(resource_group_offset,length=4,byteorder="little"))
        bw.seek(mark,0)
    entry_offset_list.append(bw.tell()-168)#script entry offset
    script_directory=Path.join(directory,"$data.dts","Script")
    if Path.exists(script_directory):
        files=list(map(lambda x:Path.join(script_directory,x),packinfo["scripts"]))
        bw.write(int.to_bytes(len(files),length=4,byteorder="little"))
        for filepath in files:
            releative_path=Path.relpath(filepath,script_directory)
            write_string(bw,releative_path)
            with open(filepath,"rb") as br:
                data=br.read()+b'\x00\x00'
                bw.write(int.to_bytes(len(data),length=4,byteorder="little"))
                bw.write(data)
    material_directory=Path.join(directory,"$data.dts","Material")
    if Path.exists(material_directory):
        files=list[str]()
        for curdir,_,filenames in os.walk(material_directory):
            for filename in filenames:
                files.append(Path.join(curdir,filename))
        bw.write(int.to_bytes(len(files),length=4,byteorder="little"))
        for filepath in files:
            releative_path=Path.relpath(filepath,material_directory)
            write_string(bw,releative_path)
            with open(filepath,"rb") as br:
                data=br.read()
                bw.write(int.to_bytes(len(data),length=4,byteorder="little"))
                bw.write(data)
    entry_offset_list.insert(0,bw.tell()-168)#project offset
    with open(Path.join(directory,"$data.dts","Project.srpgs"),"rb") as br:
        project_data=br.read()
        if is_encrypted:
            project_data=encrypt_asset(project_data,password)
        bw.write(project_data)
    bw.seek(entry_offset_mark,0)
    for offset in entry_offset_list:
        bw.write(int.to_bytes(offset,length=4,byteorder="little"))

# encrypt srk files
for entry_name in known_entry_names:
    entry_directory=Path.join(directory,entry_name)
    if not Path.exists(entry_directory):continue
    os.makedirs(Path.join(output_direcory,entry_name),exist_ok=True)
    for curdir,_,filenames in os.walk(entry_directory):
        for filename in filenames:
            sour_filepath=Path.join(curdir,filename)
            dest_filepath=pathlib.Path(Path.join(output_direcory,entry_name,filename)).with_suffix(".srk")
            with open(sour_filepath,"rb") as br:
                with open(dest_filepath,"wb") as bw:
                    bw.write(encrypt_asset(br.read(),password))

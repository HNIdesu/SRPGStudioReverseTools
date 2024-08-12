import sys
import os
import argparse
import pathlib
import os.path as Path
from io import BufferedReader
from constants import known_entry_names

# third-party libraries
import filetype
from Crypto.Cipher import ARC4
from Crypto.Hash import MD5

class InvalidDataError(Exception):
    pass

def decrypt_asset(input_buf:bytes,password:str)->bytes:
    h = MD5.new()
    pwd=password.encode("utf-16le")
    h.update(pwd)
    key = h.digest()
    cipher = ARC4.new(key)
    decrypted_data = cipher.decrypt(input_buf)
    return decrypted_data

def extract_scripts_entry(br:BufferedReader,entry:tuple[str,int,int],savedir:str):
    (entry_name,entry_position)=entry
    scripts_count=int.from_bytes(br.read(4),byteorder="little")
    for _ in range(0,scripts_count):
        script_path=br.read(int.from_bytes(br.read(4),byteorder="little"))[:-2].decode("utf-16le")
        script_length=int.from_bytes(br.read(4),byteorder="little")
        script_data=br.read(script_length)[:-2].decode("utf-16le")
        script_save_path=Path.join(savedir,entry_name,script_path)
        os.makedirs(Path.dirname(script_save_path),exist_ok=True)
        with open(script_save_path,"w",encoding="utf-8") as sw:
            sw.write(script_data)
        print(script_save_path)

def extract_entry(br:BufferedReader,entry:tuple[str,int,int],password:str|None,savedir:str):
    (entry_name,entry_position)=entry
    resource_group_count=int.from_bytes(br.read(4),byteorder="little")
    if resource_group_count==0:
        return
    offsets=list[int]()
    for _ in range(0,resource_group_count+1):
        offsets.append(int.from_bytes(br.read(4),byteorder="little"))
    for i in range(0,resource_group_count):
        resource_group_position=offsets[i]+entry_position
        br.seek(resource_group_position,0)
        resource_group_name=br.read(int.from_bytes(br.read(4),byteorder="little"))[:-2].decode("utf-16le")
        resource_group_name=resource_group_name.strip()
        _=br.read(8)
        resource_count=int.from_bytes(br.read(4),byteorder="little")
        resource_lengths=list[int]()
        for _ in range(0,resource_count):
            resource_lengths.append(int.from_bytes(br.read(4),byteorder="little"))
        for i in range(0,resource_count):
            resource_length=resource_lengths[i]
            data=None
            if password:
                encrypted_data=br.read(resource_length)
                data=decrypt_asset(encrypted_data,password)
            else:
                data=br.read(resource_length)
            ext=filetype.guess_extension(data)
            if ext:
                ext="."+ext
            else:
                ext=".unknown"
            
            if resource_count==1:
                resource_group_save_dir=Path.join(savedir,entry_name)
                os.makedirs(resource_group_save_dir,exist_ok=True)
                resource_save_path=Path.join(resource_group_save_dir,f"{resource_group_name}{ext}")
            else:
                resource_group_save_dir=Path.join(savedir,entry_name,resource_group_name)
                os.makedirs(resource_group_save_dir,exist_ok=True)
                resource_save_path=Path.join(resource_group_save_dir,f"{i:04d}{ext}")
            with open(resource_save_path,"wb") as bw:
                bw.write(data)
            print(resource_save_path)

def extract_dts(filepath:str,password:str|None,savedir:str):
    print(f"start to extract {filepath}")
    os.makedirs(savedir,exist_ok=True)
    filesize=os.stat(filepath).st_size
    with open(filepath,"rb") as br:
        signature=br.read(4)
        if signature != b"SDTS":
            raise InvalidDataError("signature mismatch")
        is_encrypted=int.from_bytes(br.read(4),byteorder="little")==1
        if is_encrypted and (not password):
            raise InvalidDataError("password is required")
        if not is_encrypted:password=None
        version=int.from_bytes(br.read(4),byteorder="little")
        _=br.read(8)
        project_position=int.from_bytes(br.read(4),byteorder="little")+168
        project_length=filesize-project_position
        offsets=list[int]()
        for _ in range(0,len(known_entry_names)):
            offsets.append(int.from_bytes(br.read(4),byteorder="little"))
        for i in range(0,len(known_entry_names)):
            entry_position=offsets[i]+168
            entry_name=known_entry_names[i]
            br.seek(entry_position,0)
            if((i+1)<len(offsets)):
                if(offsets[i+1]-offsets[i]==0):continue
                extract_entry(br,(entry_name,entry_position),password,savedir)
            else:
                if(project_position-entry_position==0):continue
                extract_scripts_entry(br,(entry_name,entry_position),savedir)
        project_file_path=Path.join(savedir,"Project.srpgs")
        with open(project_file_path,"wb") as bw:
            br.seek(project_position)
            data=br.read(project_length)
            if password:
                data=decrypt_asset(data,password)
            bw.write(data)
        print(project_file_path)

def extract_srk(filepath:str,password:str,savedir:str):
    print(f"start to decrypt {filepath}")
    os.makedirs(savedir,exist_ok=True)
    raw_data=None
    with open(filepath,"rb") as br:
        raw_data=decrypt_asset(br.read(),password)
    ext=filetype.guess_extension(raw_data)
    if ext:
        ext="."+ext
    else:
        ext=".unknown"
    save_path=pathlib.Path(Path.join(savedir,Path.basename(filename))).with_suffix(ext)
    with open(save_path,"wb") as br:
        br.write(raw_data)
    print(f"file saved to {save_path.absolute()}")
    
parser=argparse.ArgumentParser()
parser.add_argument("game_directory")
parser.add_argument("-p","--password",required=False ,default="key")
parser.add_argument("-o","--output_directory",required=False ,default="output")

args=parser.parse_args(sys.argv[1:])

game_directory:str=args.game_directory
password:str=args.password
output_directory:str=args.output_directory

try:
    for rootdir,_,filenames in os.walk(game_directory):
        for filename in filenames:
            if filename == "data.dts":
                extract_dts(Path.join(rootdir,filename),password,output_directory)
            elif filename.endswith(".srk"):
                extract_srk(Path.join(rootdir,filename),password,Path.join(output_directory,Path.relpath(rootdir,game_directory)))
    print("completed")
except InvalidDataError as e:
    print(e)

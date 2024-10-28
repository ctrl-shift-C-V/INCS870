import argparse
import pyzipper
import sys,re,pdb
import os
import gzip 
import pefile
import math
import json
from elftools.elf.elffile import ELFFile

ZF_PASS="infected"
FILE_INDEX="/mnt/d/mal.bazaar/conf/files.index.gz"
ZIP_DIR="/mnt/d/mal.bazaar/dat/"
INSTR_DIR="/mnt/d/mal.bazaar/insights"
SAM_DIR="/mnt/d/mal.bazaar/sams/"
KEEP_SAM=False
KEEP_IDB=False
DEBUG_MODE=False

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    byte_count = [0] * 256
    for byte in data:
        byte_count[byte] += 1
    for count in byte_count:
        if count == 0:
            continue
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return entropy

def calc_entropy_seq(data, chunk_size = 256):
    entropy_seq=[]
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        # Pad the last chunk if it's smaller than chunk_size
        if len(chunk) < chunk_size:
            chunk = chunk.ljust(chunk_size, b'\x00')

        # Calculate and print entropy for the current chunk
        entropy = calculate_entropy(chunk)
        #print(f'Chunk {i // chunk_size + 1} Entropy: {entropy:.4f}')
        entropy_seq.append(entropy)

    return entropy_seq

def calc_entropy_pe(file_path):
    pe = pefile.PE(file_path)
    entropies={}
    for section in pe.sections:
        data = section.get_data()
        entropy_seq=calc_entropy_seq(data) 
        entropies[section.Name.decode().strip()]=entropy_seq
    return entropies

def calc_entropy_elf(file_path):
    # Open the ELF file in binary mode
    entropies={}
    with open(file_path, 'rb') as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            try:
                if len(section.name) == 0: continue
                data = section.data()
            except Exception as e:
                continue
            entropy_seq=calc_entropy_seq(data) 
            entropies[section.name.strip()]=entropy_seq
    return entropies
        
def unzip_a_file(zf, fname, forced):
    global DEBUG_MODE
    
    fhash=fname.split(".")[0]
    fpath=os.path.join(SAM_DIR, fname+".sam")
    # since it's dangerous to save the extracted file with its original suffix, e.g., ".exe", a new extraction method is used: Extract the file content without writing it yet, then write to a renamed file
    file_content = zf.read(fname)
    # Write the extracted file to a new file with a different name
    with open(fpath, 'wb') as fd:
        fd.write(file_content)
    if DEBUG_MODE is True: print(f"{fname} has been extracted to {fpath}")
    return fpath

def analyze_the_specified_file(fpath, fname):
    global DEBUG_MODE
    
    insight_file="d:\\mal.bazaar\\insights\\%s.insight" % fname
    insight_file_in_wsl="/mnt/d/mal.bazaar/insights/%s.insight" % fname
    if os.access(insight_file, os.F_OK) and forced is False:
        print(f"{insight_file_in_wsl} already existed!")
        return None

    #pdb.set_trace()
    
    # 1, analyze with ida
    #"/mnt/d/Program Files/IDA 7.2/ida64.exe" -A -S"d:\mal.bazaar\bin\ida_dump_insight.py d:\mal.bazaar\insights\ddc5b91adaa57e853253e12d8a17fab4b02bf8aca5fff9c83c7442e9ea63a993.insight 1" "d:\mal.bazaar\sam.pe\ddc5b91adaa57e853253e12d8a17fab4b02bf8aca5fff9c83c7442e9ea63a993.exe.sam"
    #cmdline="\"/mnt/d/Program Files/IDA 7.2/ida64.exe\" -A -S\"d:\\ida.scripts\\ida_dump_insight.py %s 1\" \"d:\\mal.bazaar\\sams\\%s.sam\"" % (insight_file, fname)
    cmdline="\"/mnt/d/Program Files/IDA 7.2/ida64.exe\" -A -S\"d:\\ida.scripts\\ida_func_insight.py %s 1\" \"d:\\mal.bazaar\\sams\\%s.sam\"" % (insight_file, fname)
    if DEBUG_MODE is True: print(f"SAM: {fpath}\nIDA_CMDLINE: {cmdline}")
    os.system(cmdline)
    
    # 2, calc entropy 
    entropies={} 
    if '.exe' in fname or '.dll' in fname:
        entropies= calc_entropy_pe(fpath)
    elif '.elf' in fname:
        entropies=calc_entropy_elf(fpath)

    # remove sam and its idb file
    try:
        if not KEEP_IDB: os.unlink(fpath+".i64")
    except Exception as e:
        pass
    
    # load the IDAPython result and save entropy information into it
    if os.access(insight_file_in_wsl, os.F_OK) is False:
        print(f"Failed to generate insights for {fname}!")
        return 

    with open(insight_file_in_wsl) as fd:
        jr=json.load(fd)
    
    jr['entropies']=entropies
    with open(insight_file_in_wsl, "w", encoding='utf-8') as fd:
        json.dump(jr, fd)
    print(f"New insight: {insight_file_in_wsl}")

def analyze_in_batch(zip_file, forced=False):
    #zip_file.testzip()  # Test if the password works
    # List all the files inside the ZIP archive
    file_info_list = zip_file.infolist()

    # Analyze the samples one by one
    for file_info in file_info_list:
        # only PE and ELF
        fname=file_info.filename
        if '.dll' not in fname and '.exe' not in fname and '.elf' not in fname: continue
        try:
            print(f"To sleuth {fname}")
            fpath=unzip_a_file(zip_file, fname, forced)
            if fpath is not None:
                analyze_the_specified_file(fpath, fname)
            if not KEEP_SAM: os.unlink(fpath)
        except Exception as e:
            print("Exception \"%s\" on %s!" % (str(e), file_info.filename))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Query sample information by Hash or File.')
    parser.add_argument('--zip', dest='zip_file', type=str, help='The zip file where samples were archived, e.g. 2024-09-01.zip.')
    parser.add_argument('--hash', dest='fhash', type=str, help='Only extract and analyze the specified file from the assigned .zip.')
    parser.add_argument('-f', '--force', action='store_true', default=False, help='Whether overwrite exiting .insight file (default is False).')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='Showing debug messages')
    parser.add_argument('--keep-sam', action='store_true', dest='keep_sam', default=False, help='Whether keep the sample for later analysis.')
    parser.add_argument('--keep-idb', action='store_true', dest='keep_idb', default=False, help='Whether keep the .idb/.i64 file for later analysis.')
    args = parser.parse_args()

    if args.zip_file is None and args.fhash is None:
        parser.error("Either .zip file or a file hash must be assigned!")
        exit(0)

    DEBUG_MODE=args.debug
    KEEP_SAM=args.keep_sam
    KEEP_IDB=args.keep_idb

    fhash = None
    # locate the zip file
    if args.zip_file is not None:
        zip_fname=args.zip_file
    else:
        fhash = args.fhash
        # locate the source .zip file
        with gzip.open(FILE_INDEX, 'rt') as file:  # 'rt' mode opens the file for reading text
            for line in file:
                # 2024-09-01, 61e866e84cd071d417dc9c21bbd238c72b958414e697ec99346f0896c4185a7a.exe, 24198984 bytes
                if fhash not in line: continue
                strs=line.split(", ")
                zip_fname=os.path.join(ZIP_DIR, strs[0]+".zip")
                fname = strs[1]
                print(f"{fhash} has been located in {zip_fname}!")
                break
    try:
        zip_file = pyzipper.AESZipFile(zip_fname, 'r') 
        zip_file.pwd = ZF_PASS.encode('utf-8')

        if fhash is not None:
            fpath=unzip_a_file(zip_file, fname, args.force)
            if fpath is not None:
                print(f"To sleuth {fname}")
                analyze_the_specified_file(fpath, fname)
                if not KEEP_SAM: os.unlink(fpath)
        else:
            analyze_in_batch(zip_file, args.force)
    except Exception as e:
        print("Exception %s on %s!" % (str(e), args.zip_file))


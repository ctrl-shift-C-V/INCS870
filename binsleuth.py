import argparse
import logging
import pyzipper
import sys,re,pdb
import os,base64
import gzip 
import pefile
import math
import json
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import hashlib

ZF_PASS="infected"
LOG_FILE_PATH = "/var/log/binsleuth.log"
LOGGER=None
SAM_SRC="/mnt/d/malware.research/conf/sample.source.gz"
ZIP_DIR="/mnt/d/malware.research/dat/"
#INSIGHT_DIR="D:\\malware.research\\insights"
INSIGHT_DIR_WSL="/mnt/d/malware.research/insights"
SAM_DIR="/mnt/d/malware.research/sams/"
IDA_BIN="\"/mnt/d/Program Files/IDA 7.2/ida64.exe\" -A -S\"d:\\ida.scripts\\ida_func_insight.py %s 1\" \"%s\"" 
KEEP_SAM=False
KEEP_IDB=False
NO_IDA=False
DEBUG_MODE=False

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        LOGGER.error(f"{file_path} not found!")
    except Exception as e:
        LOGGER.error(f"Error on {file_path}: {e}!")
    return None
    
def setup_file_logger(log_file_path):
    try:
        # Create a logger
        logger = logging.getLogger("BinSleuth")
        logger.setLevel(logging.INFO)  # Set the minimum logging level

        # Create a file handler
        file_handler = logging.FileHandler(log_file_path)

        # Create a formatter for the log messages
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Attach the formatter to the handler
        file_handler.setFormatter(formatter)
        
        # Add the handler to the logger
        logger.addHandler(file_handler)

    except Exception as e:
        return None
    return logger

def convert_path(path):
    # Check if it's a Windows path
    if re.match(r'^[A-Za-z]:\\', path):
        # Convert Windows path to WSL format
        drive_letter = path[0].lower()
        wsl_path = path[2:].replace('\\', '/')
        return f"/mnt/{drive_letter}{wsl_path}"
    elif path.startswith('/mnt/') and len(path) > 5 and path[4] == '/':
        # Convert WSL path to Windows format
        drive_letter = path[5].upper()
        win_path = path[6:].replace('/', '\\')
        return f"{drive_letter}:{win_path}"
    else:
        raise ValueError("Invalid path format. Please provide a valid Windows or WSL path.")

def get_imports(pe):
    try:
        imports={}
        # Check for imported DLLs and APIs
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                mod= entry.dll.decode('utf-8')
                imports[mod]=[]
                #print(f"Module: {mod}")
                for imp in entry.imports:
                    api_name = imp.name.decode('utf-8') if imp.name else None
                    #print(f"  API: {api_name}")
                    imports[mod].append(api_name)
            return imports
        else:
            print("No imported APIs found.")
    except FileNotFoundError:
        print("File not found.")
    except pefile.PEFormatError:
        print("Not a valid PE file.")
    return {}

def get_imports_elf(elf):
    # Find the symbol table
    funcs=[]
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection): continue

        for symbol in section.iter_symbols():
            # Check if the symbol is an imported function
            if symbol.entry['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] == 'SHN_UNDEF':
                sym_name=symbol.name
                if '@' in sym_name: funcs.append(sym_name)
    
    # the .dynsym is to keep compatible with the results from IDA Pro
    return {'.dynsym':funcs}

# Function to extract PE headers and disassemble code sections
def parse_pe_header(pe):
    try:
        # Extract raw header
        dos_header_dict = {
            "e_magic": hex(pe.DOS_HEADER.e_magic),
            "e_cblp": hex(pe.DOS_HEADER.e_cblp),
            "e_cp": hex(pe.DOS_HEADER.e_cp),
            "e_crlc": hex(pe.DOS_HEADER.e_crlc),
            "e_cparhdr": hex(pe.DOS_HEADER.e_cparhdr),
            "e_minalloc": hex(pe.DOS_HEADER.e_minalloc),
            "e_maxalloc": hex(pe.DOS_HEADER.e_maxalloc),
            "e_ss": hex(pe.DOS_HEADER.e_ss),
            "e_sp": hex(pe.DOS_HEADER.e_sp),
            "e_csum": hex(pe.DOS_HEADER.e_csum),
            "e_ip": hex(pe.DOS_HEADER.e_ip),
            "e_cs": hex(pe.DOS_HEADER.e_cs),
            "e_lfarlc": hex(pe.DOS_HEADER.e_lfarlc),
            "e_ovno": hex(pe.DOS_HEADER.e_ovno),
            "e_oemid": hex(pe.DOS_HEADER.e_oemid),
            "e_oeminfo": hex(pe.DOS_HEADER.e_oeminfo),
            "e_lfanew": hex(pe.DOS_HEADER.e_lfanew)  # This points to the NT Headers
        }

        # Extract the NT Header (File Header) fields
        nt_header_dict = {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": hex(pe.FILE_HEADER.TimeDateStamp),
            "PointerToSymbolTable": hex(pe.FILE_HEADER.PointerToSymbolTable),
            "NumberOfSymbols": pe.FILE_HEADER.NumberOfSymbols,
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "Characteristics": hex(pe.FILE_HEADER.Characteristics)
        }

        # Extract the Optional Header fields
        optional_header_dict = {
            "Magic": hex(pe.OPTIONAL_HEADER.Magic),
            "EntryPointAddress": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "ImageBase": hex(pe.OPTIONAL_HEADER.ImageBase),
            "SectionAlignment": hex(pe.OPTIONAL_HEADER.SectionAlignment),
            "FileAlignment": hex(pe.OPTIONAL_HEADER.FileAlignment),
            "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "DllCharacteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
            "SizeOfImage": hex(pe.OPTIONAL_HEADER.SizeOfImage),
            "SizeOfHeaders": hex(pe.OPTIONAL_HEADER.SizeOfHeaders),
            "SizeOfStackReserve": hex(pe.OPTIONAL_HEADER.SizeOfStackReserve),
            "SizeOfStackCommit": hex(pe.OPTIONAL_HEADER.SizeOfStackCommit),
            "SizeOfHeapReserve": hex(pe.OPTIONAL_HEADER.SizeOfHeapReserve),
            "SizeOfHeapCommit": hex(pe.OPTIONAL_HEADER.SizeOfHeapCommit),
            "LoaderFlags": hex(pe.OPTIONAL_HEADER.LoaderFlags),
            "NumberOfRvaAndSizes": pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        }

         # Extract Section headers
        section_headers = []
        for section in pe.sections:
            try:
                sname=section.Name.decode('utf-8').strip().strip('\x00')
            except:
                sname=base64.b64encode(section.Name).decode()
            section_data = {
                "Name":sname,
                "VirtualAddress": hex(section.VirtualAddress),
                "SizeOfRawData": hex(section.SizeOfRawData),
                "PointerToRawData": hex(section.PointerToRawData),
                "Characteristics": hex(section.Characteristics)
            }
            section_headers.append(section_data)

        # Combine all headers into one dictionary
        pe_headers_dict = {
            #"File_Hash": file_name,
            "DOS_Header": dos_header_dict,
            "NT_Header": nt_header_dict,
            "Optional_Header": optional_header_dict,
            "Section_Headers": section_headers
        }
        
        '''
        if DEBUG_MODE is True:
            pe_headers_json = json.dumps(pe_headers_dict, indent=4)
            print(pe_headers_json)
        '''
        return pe_headers_dict  #all_pe_data.append(pe_headers_dict)

    except Exception as e:
        print(f"Exception caught: {e}")
    return None

# Function to extract ELF headers and disassemble code sections
def parse_elf_header(elf):
    try:
        elf_header_dict = {
            "EI_CLASS": elf.header['e_ident']['EI_CLASS'],
            "EI_DATA": elf.header['e_ident']['EI_DATA'],
            "EI_VERSION": elf.header['e_ident']['EI_VERSION'],
            "EI_OSABI": elf.header['e_ident']['EI_OSABI'],
            "Type": elf.header['e_type'],
            "Machine": elf.header['e_machine'],
            "Version": elf.header['e_version'],
            "EntryPointAddress": hex(elf.header['e_entry']),
            "ProgramHeaderOffset": hex(elf.header['e_phoff']),
            "SectionHeaderOffset": hex(elf.header['e_shoff']),
            "Flags": hex(elf.header['e_flags']),
            "HeaderSize": elf.header['e_ehsize'],
            "ProgramHeaderEntrySize": elf.header['e_phentsize'],
            "ProgramHeaderCount": elf.header['e_phnum'],
            "SectionHeaderEntrySize": elf.header['e_shentsize'],
            "SectionHeaderCount": elf.header['e_shnum'],
            "SectionHeaderStringTableIndex": elf.header['e_shstrndx']
        }

        # Extract the Program Header fields
        program_headers = []
        for i in range(elf.num_segments()):
            segment = elf.get_segment(i)
            program_headers.append({
                "Type": segment['p_type'],
                "Offset": hex(segment['p_offset']),
                "VirtualAddress": hex(segment['p_vaddr']),
                "PhysicalAddress": hex(segment['p_paddr']),
                "FileSize": hex(segment['p_filesz']),
                "MemorySize": hex(segment['p_memsz']),
                "Flags": hex(segment['p_flags']),
                "Alignment": hex(segment['p_align'])
            })

        # Extract the Section Header fields
        section_headers = []
        for i in range(elf.num_sections()):
            section = elf.get_section(i)
            section_headers.append({
                "Name": section.name,
                "Type": section['sh_type'],
                "Flags": hex(section['sh_flags']),
                "Address": hex(section['sh_addr']),
                "Offset": hex(section['sh_offset']),
                "Size": hex(section['sh_size']),
                "Link": section['sh_link'],
                "Info": section['sh_info'],
                "AddressAlignment": hex(section['sh_addralign']),
                "EntrySize": hex(section['sh_entsize'])
            })

        # Combine all headers into one dictionary
        elf_headers_dict = {
            "ELF_Header": elf_header_dict,
            "Program_Headers": program_headers,
            "Section_Headers": section_headers
        }

        #all_elf_data.append(elf_headers_dict)
        return elf_headers_dict

    except Exception as e:
        print(f"Exception caught: {e}")
    return None

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

def calc_entropy_pe(pe):
    entropies={}
    for section in pe.sections:
        try:
            # invalid encoding might be encountered, e.g., 79757b669da7754fb0319e313a1c24b9c9e170b7815174ca55959eb3bbca43f3.exe  
            sname=section.Name.decode().strip().strip("\x00")
        except:
            sname=base64.b64encode(section.Name).decode('utf-8')
        if DEBUG_MODE is True: print(f"to calc entropy for section {sname}")
        data = section.get_data()
        entropy_seq=calc_entropy_seq(data) 
        entropies[sname]=entropy_seq
    return entropies

def calc_entropy_elf(elf):
    # Open the ELF file in binary mode
    entropies={}
    for section in elf.iter_sections():
        try:
            sname=section.name.strip().strip("\x00")
            if len(sname) == 0: continue
            data = section.data()
        except Exception as e:
            continue
        entropy_seq=calc_entropy_seq(data) 
        entropies[sname]=entropy_seq
    return entropies

def is_pe_or_elf(header):
    # only PE and ELF are considered
    if header[:2] == b'MZ': return True
    if header[:4] == b'\x7fELF': return True
    return False

def unzip_assigned_file(file_content, sam_dir, fname):
    global DEBUG_MODE
    
    # since it's dangerous to save the extracted file with its original suffix, e.g., ".exe", a new extraction method is used: Extract the file content without writing it yet, then write to a renamed file
    if '.sam' not in fname:
        fname=fname+".sam"

    fpath=os.path.join(sam_dir, fname)
    
    # Write the extracted file to a new file with a different name
    with open(fpath, 'wb') as fd:
        fd.write(file_content)
        if DEBUG_MODE is True: print(f"{fname} has been extracted to {fpath}")
    return fpath
        
def unzip_a_file_by_hash(zf, fhash):
    global DEBUG_MODE, SAM_DIR
    
    # since it's dangerous to save the extracted file with its original suffix, e.g., ".exe", a new extraction method is used: Extract the file content without writing it yet, then write to a renamed file
    for fi in zf.infolist():
        if fhash.lower() in fi.filename.lower():
            file_content = zf.read(fi.filename)
            return unzip_assigned_file(file_content, SAM_DIR, fi.filename)
    print(f"Failed to find {fhash} from {zf.fp}!")
    return None

def analyze_the_specified_file(fpath, fhash):
    global DEBUG_MODE, INSIGHT_DIR_WSL, NO_IDA
    
    insight_file_in_wsl=os.path.join(INSIGHT_DIR_WSL, f"{fhash}.insight")
    insight_file_in_wsl=os.path.abspath(insight_file_in_wsl)
    insight_file=convert_path(insight_file_in_wsl)
    
    # windows path is necessary for IDA Pro
    fpath_win=convert_path(os.path.abspath(fpath))
   
    # file name is used speed up the file header parsing
    fname=fpath.split("/")[-1].split(".sam")[0]

    #pdb.set_trace()
    
    # 1, analyze with ida
    #cmdline="\"/mnt/d/Program Files/IDA 7.2/ida64.exe\" -A -S\"d:\\ida.scripts\\ida_dump_insight.py %s 1\" \"d:\\malware.research\\sams\\%s.sam\"" % (insight_file, fname)
    if not NO_IDA:
        cmdline=IDA_BIN % (insight_file, fpath_win)
        if DEBUG_MODE is True: print(f"To analyzed with IDAPro,  cmdline: {cmdline}")
        LOGGER.info(f"New insight task: {cmdline}")
        os.system(cmdline)
    
    # 2, calc entropy 
    if DEBUG_MODE is True: print("To caculate the entropy sequence and parse header ...")
    entropies,header_info,imports={},{},{}
    try:
        pe = pefile.PE(fpath)
        entropies= calc_entropy_pe(pe)
        header_info=parse_pe_header(pe)
        imports=get_imports(pe)
    except:
        try:
            with open(fpath, 'rb') as f:
                elf = ELFFile(f)    
                entropies=calc_entropy_elf(elf)
                header_info=parse_elf_header(elf)
                imports=get_imports_elf(elf)
        except:
            print(f"Failed to parse unsupported file {fpath}!")
            return
        pass

    # remove sam and its idb file
    try:
        pdb.set_trace()
        if not KEEP_IDB and os.path.exists(fpath+".i64"): 
            os.unlink(fpath+".i64")
    except Exception as e:
        pass
    
    # 3, load the IDAPython result and save entropy information into it
    if DEBUG_MODE is True: print("To integrate the entropy and header parsing into the IDA insights ...")
    if os.access(insight_file_in_wsl, os.F_OK) is False:
        '''
        print(f"Failed to generate insights for {fname}!")
        return 
        '''
        jr={}

    else:
        with open(insight_file_in_wsl) as fd:
            jr=json.load(fd)
    
    jr['entropies']=entropies
    jr['headers']=header_info
    if 'imports' not in jr:
        jr['imports']=imports

    # 4, write back the integrated results
    if DEBUG_MODE is True: print("To write back the integrated insights ...")
    with open(insight_file_in_wsl, "w", encoding='utf-8') as fd:
        json.dump(jr, fd)
    print(f"New insight: {insight_file_in_wsl}")
    LOGGER.info(f"New insight: {insight_file_in_wsl}")

def analyze_in_batch(zip_file, forced=False):
    #zip_file.testzip()  # Test if the password works
    # List all the files inside the ZIP archive
    file_info_list = zip_file.infolist()

    # Analyze the samples one by one
    for file_info in file_info_list:
        # Only PE and ELF files are considered.
        # For MalwareBazaar ZIPs, the file type can be directly checked with the file name.
        # In case of VirusShare, the file type needs to be determined using the content, which is done 
        #   inside the function of unzip_assigned_file().
        fname=file_info.filename
        if '.dll' not in fname and '.exe' not in fname and '.elf' not in fname \
            and 'VirusShare' not in fname: 
            continue
        
        try:
            print(f"To sleuth {fname}")

            # check existence to avoid duplicate work
            insight_file=os.path.join(INSIGHT_DIR_WSL, f"{fname}.insight")
            insight_file=os.path.abspath(insight_file)
            if os.access(insight_file, os.F_OK) and forced is False:
                print(f"{insight_file} already existed!")
                continue
            file_content=zip_file.read(fname)
            if not is_pe_or_elf(file_content[0:128]):  
                print(f"Skip non-PE/ELF file {fname}!")
                continue
            fpath=unzip_assigned_file(file_content, SAM_DIR, fname)
            if fpath is not None:
                analyze_the_specified_file(fpath, fname)
                if not KEEP_SAM: os.unlink(fpath)
        except Exception as e:
            print("Exception \"%s\" on %s!" % (str(e), file_info.filename))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract valuable information from a sample(s).')
    parser.add_argument('--zip', dest='zip_file', type=str, help='The zip file where samples were archived, e.g. 2024-09-01.zip.')
    parser.add_argument('--hash', dest='fhash', type=str, help='Only extract and analyze the specified file from the assigned .zip.')
    parser.add_argument('--path', dest='fpath', type=str, help='The full path of the file to be sleuthed.')
    parser.add_argument('--insight-folder', dest='insight_folder', type=str, help='The folder to save the created insight file.')
    parser.add_argument('-f', '--force', action='store_true', default=False, help='Whether overwrite exiting .insight file (default is False).')
    parser.add_argument('-d', '--debug', action='store_true', default=False, help='Showing debug messages')
    parser.add_argument('--keep-sam', action='store_true', dest='keep_sam', default=False, help='Whether keep the sample for later analysis.')
    parser.add_argument('--keep-idb', action='store_true', dest='keep_idb', default=False, help='Whether keep the .idb/.i64 file for later analysis.')
    parser.add_argument('--no-ida', action='store_true', dest='no_ida', default=False, help='Whether to cancel the IDA backend analysis, default is False.')
    args = parser.parse_args()

    #pdb.set_trace()

    # set up the file logger
    LOGGER = setup_file_logger(LOG_FILE_PATH)
    if LOGGER is None:
        print("Failed to initialize the logger!")
        sys.exit(-1)

    DEBUG_MODE=args.debug
    KEEP_SAM=args.keep_sam
    KEEP_IDB=args.keep_idb
    NO_IDA=args.no_ida

    if args.insight_folder is not None:
        if not os.path.exists(args.insight_folder):
            print(f"Failed to open {zip_fname}, it does not exist!")
            sys.exit(0)
        INSIGHT_DIR_WSL=args.insight_folder

    # case 1: sleuth the files compressed in a .zip 
    zip_fname,fname,fhash = None,None,None
    if args.zip_file is not None:
        #pdb.set_trace()
        zip_fname=args.zip_file
        if not os.path.exists(zip_fname):
            print(f"Failed to open {zip_fname}, it does not exist!")
            sys.exit(0)
        try:
            zip_file = pyzipper.AESZipFile(zip_fname, 'r') 
            zip_file.pwd = ZF_PASS.encode('utf-8')
            analyze_in_batch(zip_file, args.force)
        except Exception as e:
            print("Exception %s on %s!" % (str(e), args.zip_file))
    
    # case 2: sleuth the assigned hash compressed in some .zip 
    zip_fname,fname,fhash = None,None,None
    if args.fhash is not None:
        fhash = args.fhash
        insight_file=os.path.join(INSIGHT_DIR_WSL, f"{fhash}.insight")
        if os.access(insight_file, os.F_OK) and args.force is False:
            print(f"{fhash}.insight already existed!")
            sys.exit(0)

        # 2.1, locate the source .zip file
        fi=None
        with gzip.open(SAM_SRC, 'rt') as fd:  # 'rt' mode opens the file for reading text
            for l in fd:
                lv=json.loads(l.strip())
                if lv['hash'].lower() == fhash.lower():
                    fi=lv
                    zip_fname=fi['loc']
                    zip_fname=os.path.join(ZIP_DIR, zip_fname)
                    if 'ext' in fi:
                        fname=fhash+"."+fi['ext']
                    print(f"{fhash} has been located in {zip_fname}!")
                    break
        if fi is None:
            print(f"{fhash} could not be located!")
            sys.exit(0)
        
        # check existence of the .zip file
        if not os.path.exists(zip_fname):
            print(f"Failed to open {zip_fname}, it does not exist!")
            sys.exit(0)
        
        try:
            zip_file = pyzipper.AESZipFile(zip_fname, 'r') 
            zip_file.pwd = ZF_PASS.encode('utf-8')

            fpath=None
            if fname is not None:  # for malware bazaar
                file_content=zip_file.read(fname)
                fpath=unzip_assigned_file(file_content, SAM_DIR, fname)
            elif fhash is not None:  # for Virusshare
                fpath=unzip_a_file_by_hash(zip_file, fhash)
                fname=fpath.split("/")[-1].split(".")[0]
            if fpath is not None:
                print(f"To sleuth {fhash}")
                analyze_the_specified_file(fpath, fhash)
                if not KEEP_SAM: os.unlink(fpath)
        except Exception as e:
            print("Exception %s on %s!" % (str(e), args.zip_file))
   
    # case 3: sleuth the assigned file
    zip_fname,fname,fhash = None,None,None
    if args.fpath is not None:
        fpath=os.path.abspath(args.fpath)
        fhash=calculate_md5(fpath)
        LOGGER.info(f"MD5 for {fpath}: {fhash}")
        if not os.path.exists(fpath):
            print(f"{fhash} does not exist!")
            sys.exit(0)

        #pdb.set_trace()
        insight_file=os.path.join(INSIGHT_DIR_WSL, f"{fhash}.insight")
        insight_file=os.path.abspath(insight_file)
        if os.access(insight_file, os.F_OK) and args.force is False:
            print(f"{insight_file} already existed!")
            sys.exit(0)
        
        analyze_the_specified_file(fpath, fhash)
        

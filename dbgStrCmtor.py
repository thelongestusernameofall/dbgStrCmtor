#!python
#coding=utf-8

# Author : Simon Huang
# Mail   : thelongestusernameofall@gmail.com
# Time   : '2016-06-06 11:56:58'
#

__author__ = 'simon_huang'

__version__    = "0.0.1"
__date__       = "2016-06-06 11:57:22"
__maintainer__ = "simon_huang"
__email__      = "thelongestusernameofall#gmail.com"
__copyright__  = "Copyright 2015, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "Use IDAPython"

from idaapi import *
from idautils import *
from idc import *
import traceback
import os
import sys

dbgStrCmtor=None


#333333333333333333333333333333333333333333333333333333333333333333
TEA_algorithm_name = "<<TEA>>"
TEA_algorithm_SBox = [0x9e3779b9]

SHA256_algorithm_name="<<SHA256>>"
SHA256_algorithm_SBox = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
]

SHA512_algorithm_name="<<SHA512>>"
SHA512_algorithm_SBox=[
    0x428a2f98,0xd728ae22,0x71374491,0x23ef65cd,0xb5c0fbcf,0xec4d3b2f,0xe9b5dba5,0x8189dbbc,
    0x3956c25b,0xf348b538,0x59f111f1,0xb605d019,0x923f82a4,0xaf194f9b,0xab1c5ed5,0xda6d8118,
    0xd807aa98,0xa3030242,0x12835b01,0x45706fbe,0x243185be,0x4ee4b28c,0x550c7dc3,0xd5ffb4e2,
    0x72be5d74,0xf27b896f,0x80deb1fe,0x3b1696b1,0x9bdc06a7,0x25c71235,0xc19bf174,0xcf692694,
    0xe49b69c1,0x9ef14ad2,0xefbe4786,0x384f25e3,0x0fc19dc6,0x8b8cd5b5,0x240ca1cc,0x77ac9c65,
    0x2de92c6f,0x592b0275,0x4a7484aa,0x6ea6e483,0x5cb0a9dc,0xbd41fbd4,0x76f988da,0x831153b5,
    0x983e5152,0xee66dfab,0xa831c66d,0x2db43210,0xb00327c8,0x98fb213f,0xbf597fc7,0xbeef0ee4,
    0xc6e00bf3,0x3da88fc2,0xd5a79147,0x930aa725,0x06ca6351,0xe003826f,0x14292967,0x0a0e6e70,
    0x27b70a85,0x46d22ffc,0x2e1b2138,0x5c26c926,0x4d2c6dfc,0x5ac42aed,0x53380d13,0x9d95b3df,
    0x650a7354,0x8baf63de,0x766a0abb,0x3c77b2a8,0x81c2c92e,0x47edaee6,0x92722c85,0x1482353b,
    0xa2bfe8a1,0x4cf10364,0xa81a664b,0xbc423001,0xc24b8b70,0xd0f89791,0xc76c51a3,0x0654be30,
    0xd192e819,0xd6ef5218,0xd6990624,0x5565a910,0xf40e3585,0x5771202a,0x106aa070,0x32bbd1b8,
    0x19a4c116,0xb8d2d0c8,0x1e376c08,0x5141ab53,0x2748774c,0xdf8eeb99,0x34b0bcb5,0xe19b48a8,
    0x391c0cb3,0xc5c95a63,0x4ed8aa4a,0xe3418acb,0x5b9cca4f,0x7763e373,0x682e6ff3,0xd6b2b8a3,
    0x748f82ee,0x5defb2fc,0x78a5636f,0x43172f60,0x84c87814,0xa1f0ab72,0x8cc70208,0x1a6439ec,
    0x90befffa,0x23631e28,0xa4506ceb,0xde82bde9,0xbef9a3f7,0xb2c67915,0xc67178f2,0xe372532b,
    0xca273ece,0xea26619c,0xd186b8c7,0x21c0c207,0xeada7dd6,0xcde0eb1e,0xf57d4f7f,0xee6ed178,
    0x06f067aa,0x72176fba,0x0a637dc5,0xa2c898a6,0x113f9804,0xbef90dae,0x1b710b35,0x131c471b,
    0x28db77f5,0x23047d84,0x32caab7b,0x40c72493,0x3c9ebe0a,0x15c9bebc,0x431d67c4,0x9c100d4c,
    0x4cc5d4be,0xcb3e42b6,0x597f299c,0xfc657e2a,0x5fcb6fab,0x3ad6faec,0x6c44198c,0x4a475817,
]

CRC32_algorithm_name="<<CRC32>>"
CRC32_algorithm_SBox=[
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
]

MD5_algorithm_name="<<MD5>>"
MD5_algorithm_SBox=[
    0X67452301L,0XEFCDAB89L,0X98BADCFEL,0X10325476L
]

SHA1_algorithm_name="<<SHA1>>"
SHA1_algorithm_SBox=[
    0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0
]

algorithmNameList = [
    TEA_algorithm_name,SHA256_algorithm_name,SHA512_algorithm_name,SHA1_algorithm_name,CRC32_algorithm_name,MD5_algorithm_name
]
algorithmSBoxList = [
    TEA_algorithm_SBox,SHA256_algorithm_SBox,SHA512_algorithm_SBox,SHA1_algorithm_SBox,CRC32_algorithm_SBox,MD5_algorithm_SBox
]

#jump operations
INST_JUMP = ['BLX','BL','BX','B','CBNZ','CBZ']
#arithmetic operations
INST_ADD = ['ADC','ADD']
INST_SUB = ['RSB','RSC','SBC','SUB']
INST_MUL = ['MUL','MLA'] # MLA multiple add

#Logical operations
INST_LOG = ['ORR','EOR','AND','BIC']

#Compare instructions
INST_CMP = ['CMN','CMP','TEQ','TST']

#interrupt instruction
INST_INT = ['SWI']

#Data move operations
INST_MOV = ['MOV',
            'MRC',#协处理器
            'MRS',#
            'MSR',#
            'MVN',
            'LDC',#协处理器
            'LDM',# rd为地址的内存块到寄存器组 ->
            'LDR',#内存到寄存器
            'MCR',
            'CDP',
            'STC',
            'STM',#
            'STR',
            'SWP'
]

#the 0 opnd is the destination opnd
INST_MOV_TO   = ['MOV','MVN','LDR']#'STM'
#the 0 opnd is the source, and the 1 opnd is destination
INST_MOV_BACK = ['STR']#'LDM'
#the 0 opnd is the source and destination of 1 opnd
INST_MOV_SWAP = ['SWP']

INST_SHIFT = ['LSL', 'LSR', 'ASR', 'ROR', 'RRX']


INST_DICT = {
    'JUMP':INST_JUMP,
    'ADD':INST_ADD,
    'SUB':INST_SUB,
    'MUL':INST_MUL,
    'LOG':INST_LOG,
    'CMP':INST_CMP,
    'INT':INST_INT,
    'MOV':INST_MOV,
    'SHIFT':INST_SHIFT
}

INST_CONDITION = ['EQ',
                  'NE',
                  'VS',
                  'VC',
                  'HI',
                  'LS',
                  'PL',
                  'MI',
                  'CS',
                  'CC',
                  'GE',
                  'GT',
                  'LE',
                  'LT',
                  'AL',
                  'NV',

                  'FA',
                  'FD', # note that FD is not a condition in fact.
                  'EA',
                  'ED',

                  'S'   # not a condition
]

REG_LIST = [] #R0-R15, R15=PC, R14=LR, R13=SP
for i in xrange(0,16):
    REG_LIST.append('R'+str(i))
REG_LIST.append('PC')
REG_LIST.append('LR')
REG_LIST.append('SP')

PrintableCharList = range(32,127)
PrintableCharList.append(0x0d)
PrintableCharList.append(0x0a)

#333333333333333333333333333333333333333333333333333333333333333333

STR_PREFIX = "[STR]:"
FUNC_PREFIX = "[FUNC]:"
PARA_PREFIX = "[PARAMETER]:"
RTN_PREFIX="[RETURN]:"

splitChar = [',','[',']','+','-','(',')','#','!','=']

global symbolDict
strMaxLen=100

def waitAuto():
    """
    wait for the finish of auto analysis
    """
    #print "waiting for auto process done ... "
    autoWait()


def introduction():
    print("-----------------------------------------------------------------")
    print("dbgStrCmtor: \r\n Author: Simon Huang \r\n Email: thelongestusernameofall#gmail.com\r\n")
    print("ShortCut:\r\n\tStart: alt-2\r\n\tStep Into: `-1\r\n\tStep Over:`-2\r\n")
    print("-----------------------------------------------------------------")

def init():
    #print '[init]: ...   '
    global symbolDict
    waitAuto()
    introduction()
    symbolDict = getDataSymbols()


def getDataSymbols():
    #print 'waiting for symbol parsing done ..'
    dataSectionKeywords = ['data']
    symbolDict = {}

    for ea in Segments():
        segName = SegName(ea)
        isDataSeg = False
        for aKeyWord in dataSectionKeywords:
            if aKeyWord in segName:
                isDataSeg = True
        if isDataSeg:
            startEa = SegStart(ea)
            endEa = SegEnd(ea)
            aLocation = startEa
            #for aLocation in xrange(startEa,endEa):
            while aLocation<endEa:
                lName = Name(aLocation)
                if lName and len(lName.strip())>0:
                    symbolDict[lName.strip()] = aLocation
                aLocation+=1
    return symbolDict


def cleanMnem(instMnem):
    """:type instMnem str"""
    instMnem = instMnem.upper()
    for aC in INST_CONDITION:
        """:type aC str"""
        if instMnem.endswith(aC):
            instMnem.replace(aC,"")
    return instMnem


def isANum(aStr):
    """:type aStr str"""
    try:
        aStr = aStr.replace("#","").replace("=","").strip()
        if aStr.lower().startswith("0x"):
            intvalue = int(aStr,16)
            return True
        else:
            intvalue = int(aStr,10)
        return True
    except Exception as e:
        return False


def getANum(aStr):
    """:type aStr str"""
    intValue = -1
    aStr = aStr.replace("#","").replace("=","").strip()
    if aStr.lower().startswith("0x"):
        intValue = int(aStr,16)
    else:
        intValue = int(aStr,10)
    return intValue


def tokenizeOpnd(opndStrValue):
    tokenList = []

    aToken = ''
    for achar in opndStrValue:
        if achar==' ':
            continue
        if achar in splitChar:
            if len(aToken) > 0:
                tokenList.append(aToken)
            tokenList.append(achar)
            aToken = ''
        else:
            aToken+=achar
    if len(aToken) > 0:
        tokenList.append(aToken)
    #print tokenList
    return tokenList


def makeSuffixExp(tokenList):
    suffixExp = []
    operationStack = []
    for aToken in tokenList:
        if aToken in splitChar:
            if aToken in ["(","["]:
                operationStack.append(aToken)
            elif aToken in [',','+','-']:
                while 1:
                    if len(operationStack) == 0:
                        operationStack.append(aToken)
                        break
                    elif operationStack[-1] in [',','+','-']:
                        suffixExp.append(operationStack.pop())
                    else:
                        operationStack.append(aToken)
                        break
            elif aToken==')':
                while 1:
                    if len(operationStack) == 0:
                        break
                    elif operationStack[-1] != '(':
                        suffixExp.append(operationStack.pop())
                    else:
                        operationStack.pop()
                        break
            elif aToken==']':
                while 1:
                    if len(operationStack) == 0:
                        break
                    elif operationStack[-1] != '[':
                        suffixExp.append(operationStack.pop())
                    else:
                        operationStack.pop()
                        break

        else:
            suffixExp.append(aToken)
    while 1:
        if len(operationStack) > 0:
            suffixExp.append(operationStack.pop())
        else:
            break
    #print "suffixExp:",suffixExp
    return suffixExp


def getOpndDataValue(opndStrValue):
    """:type opndStrValue str"""

    tokenList = tokenizeOpnd(opndStrValue)
    suffixExp = makeSuffixExp(tokenList)
    valueStack = []

    odv = 0

    for aToken in suffixExp:
        tokenV = -1
        if aToken not in ["+","-",","]:
            if isANum(aToken):
                tokenV = getANum(aToken)
            elif aToken in REG_LIST:
                tokenV = GetRegValue(aToken)
            elif aToken in symbolDict:
                tokenV = symbolDict[aToken]
            elif aToken.lower().startswith("var_"):
                try:
                    tokenV = int(aToken.lower().replace("var_","-0x"),16)
                except Exception as e:
                    print e.message
                    traceback.print_exc()
                    pass
            elif aToken.lower().startswith("dword_"):
                try:
                    tokenV = int(aToken.lower().replace("dword_","0x"),16)
                except Exception as e:
                    traceback.print_exc()
                    print e.message
                    pass
            else:
                print "UNDEFINED:" + aToken
                pass

            valueStack.append(tokenV)
        elif aToken in ["+",","]:
            oper_2 = valueStack.pop()
            oper_1 = valueStack.pop()
            valueStack.append(oper_1+oper_2)
        elif aToken in ["-"]:
            oper_2 = valueStack.pop()
            oper_1 = 0
            if len(valueStack)>0:
                oper_1 = valueStack.pop()
            valueStack.append(oper_1-oper_2)

    assert len(valueStack)==1
    odv = valueStack.pop()
    odv = odv&0xffffffff
    return odv


def getSourceData(instMnem,instOpndList):
    if not instMnem or not instOpndList or len(instOpndList)==0:
        return None

    srcData = 0
    idx = 1

    if instMnem in INST_ADD:
        if len(instOpndList) == 2:
            srcData = getOpndDataValue(instOpndList[0]) + getOpndDataValue(instOpndList[1])
        elif len(instOpndList) ==3:
            srcData = getOpndDataValue(instOpndList[2]) + getOpndDataValue(instOpndList[1])
    elif instMnem in INST_SUB :
        if len(instOpndList) == 2:
            srcData = getOpndDataValue(instOpndList[0]) - getOpndDataValue(instOpndList[1])
        elif len(instOpndList) ==3:
            srcData = getOpndDataValue(instOpndList[1]) - getOpndDataValue(instOpndList[2])
    elif  instMnem in INST_MUL:
        if len(instOpndList) == 2:
            srcData = getOpndDataValue(instOpndList[0]) *getOpndDataValue(instOpndList[1])
        elif len(instOpndList) ==3:
            srcData = getOpndDataValue(instOpndList[1]) *getOpndDataValue(instOpndList[2])

    elif instMnem in INST_MOV_BACK:
        srcData = getOpndDataValue(instOpndList[0])
    elif instMnem in INST_MOV_TO:
        srcData = getOpndDataValue(instOpndList[1])
    elif instMnem in INST_MOV_SWAP: # only process the later opnd for simple
        srcData = getOpndDataValue(instOpndList[1])

    elif instMnem in INST_JUMP:
        pass #process JMP instruction

    return srcData

def updateSymbolDict(instLocation):
    instName = Name(instLocation)
    global symbolDict
    if instName and len(instName.strip())>0 and instName.strip() not in symbolDict:
        symbolDict[instName] = instLocation


def getAlgorithmName(memLocation):
    #print "getAlgorithmName : ",memLocation
    for i in xrange(0,len(algorithmSBoxList)):
        if memLocation in algorithmSBoxList[i]:
            return algorithmNameList[i]
    return None


def readMemAsStr(memLocation):
    i=0
    strValue=None
    tmpV = Byte(memLocation)

    isAStr = True

    if tmpV and tmpV in PrintableCharList:
        strValue=chr(tmpV)
        for i in xrange(1,strMaxLen):
            tmpV = Byte(memLocation+i)
            if tmpV==0:
                break
            if tmpV not in PrintableCharList:
                isAStr = False
                break

            strValue += chr(tmpV)

    possibleAlgorithmName = getAlgorithmName(memLocation)


    if strValue:
        #print isAStr,strValue
        pass

    if not isAStr:
        strValue=None

    if possibleAlgorithmName:
        if not strValue:
            strValue=possibleAlgorithmName
        else:
            strValue=strValue+"||"+possibleAlgorithmName
    return strValue


def getMemLinkedList(memLocation):
    """:type memLocation int"""
    if not memLocation or memLocation == 0:
        return None

    memList = [memLocation]
    #strList.append(readMemAsStr(memLocation))

    nMemLocation = Dword(memLocation)
    while nMemLocation and nMemLocation!=0xffffffff and nMemLocation not in memList:
        memList.append(nMemLocation)
        nMemLocation=Dword(nMemLocation)

    return memList


def getMemLinkedStrList(memList):
    if not memList:
        return None
    strList = []
    for aMem in memList:
        strList.append(readMemAsStr(aMem))

    return strList


def getOldComment(memLocation):
    oldCmt_rep = GetCommentEx(memLocation,1)
    #print 'oldCmt_rep:',oldCmt_rep
    oldCmt = GetCommentEx(memLocation,0)
    #print 'oldCmt:',oldCmt
    if not oldCmt:
        oldCmt=oldCmt_rep
    else:
        if oldCmt_rep:
            oldCmt = oldCmt + "\r\n"+oldCmt_rep
    return oldCmt


def addComment(memLocation,commentStr):
    #print 'addComment: location:',memLocation,"commentStr:",commentStr
    oldCmt = getOldComment(memLocation)
    #print "oldCtm:",oldCmt
    """:type oldCmt str"""

    cmtStr=""
    if not oldCmt or not oldCmt.strip().startswith(STR_PREFIX):
        if not oldCmt or len(oldCmt.strip())==0:
            cmtStr=STR_PREFIX+commentStr
        else:
            cmtStr=STR_PREFIX+commentStr+"\r\n"+oldCmt

        MakeRptCmt(memLocation,cmtStr)
    else:
        # if oldCmt.strip()!=(STR_PREFIX+commentStr).strip():
        #     cmtStr=oldCmt+"\r\n"+commentStr
        #     print "2.cmtStr:",cmtStr
        #     MakeRptCmt(memLocation,cmtStr)
        oldCmts = oldCmt.split('\r\n')
        """:type oldCmts list of str"""
        isContain=False
        for aOldCmt in oldCmts:
            aOldCmt=aOldCmt.strip()
            if aOldCmt.startswith(STR_PREFIX):
                if aOldCmt==(STR_PREFIX+commentStr).strip():
                    isContain=True
                    break
            elif aOldCmt==commentStr.strip():
                isContain=True
                break
        if not isContain:
            cmtStr=oldCmt.strip()+"\r\n"+commentStr
            MakeRptCmt(memLocation,cmtStr)


def addComments(memList):
    strList = getMemLinkedStrList(memList)
    #print "strList",strList
    i=len(memList)
    cmtStr=None
    while i>0:
        i-=1
        aMem = memList[i]
        aStr = strList[i]
        """:type aStr str"""
        if aStr and len(aStr.strip())>0:
            if not cmtStr or len(cmtStr.strip())==0:
                cmtStr=aStr
            else:
                cmtStr=aStr+"->"+cmtStr
        if cmtStr and len(cmtStr.strip())>0:
            addComment(aMem,cmtStr)
    #print cmtStr
    return cmtStr


def isFuncStart(instLocation):
    funcInnerOffset = GetFuncOffset(instLocation)
    if not funcInnerOffset:
        return False
    if not "+" in funcInnerOffset:
        return True
    elif funcInnerOffset.endswith('+1'):  #Thumb mode, Sometimes jump to functionStart + 1
        return True
    return False


def cmtFuncParameters(instLocatin, inst_mnem):

    # if the function already be commented by this tool, no more comment should be done.
    # function should be more considering its logic than its parameters each time.

    oldCmt =  getOldComment(instLocatin)
    if oldCmt and  FUNC_PREFIX in oldCmt:
        return

    if inst_mnem in INST_JUMP:
        xrefObjList = [ref for ref in XrefsFrom(instLocatin,1)]
        if len(xrefObjList) !=1:
            print("[ERROR]: should be 1, something goes wrong"+"instLocation:"+str(instLocatin))
            return
        targetLocation = xrefObjList[0].to
        if isFuncStart(targetLocation):
            functionCmtStr = FUNC_PREFIX + "-"*20 + "\r\n" + PARA_PREFIX

            for i in xrange(0,3):
                R_value = GetRegValue("R"+str(i))
                R_str = "R"+str(i)+"="+hex(R_value).replace("L","")+"="+str(R_value)
                R_MemList = getMemLinkedList(R_value)
                R_MemStrList = getMemLinkedStrList(R_MemList)
                strAppend = ""
                if R_MemStrList and len(R_MemStrList) > 1:
                    for aMemStr in R_MemStrList:
                        if aMemStr and len(aMemStr.strip())>0:
                            strAppend+=aMemStr + " -> "
                R_str = R_str + " : " + strAppend + "\r\n"
                functionCmtStr += R_str

            #functionCmtStr += "[FUNC]:" + "-"*10
            MakeComm(instLocatin,functionCmtStr) # maybe MakeRptCmt better?



def getPrevInstLocation(instLocation):
    xrefsList = [ref for ref in XrefsTo(instLocation,0)]

    if len(xrefsList) == 1:
        xrefObj = xrefsList[0]
        frmLocation = xrefObj.frm
        return frmLocation

    return None


def isPrevInstJmp(instLocation):
    prevInstLocation = getPrevInstLocation(instLocation)
    if not prevInstLocation:
        return False
    prev_inst_mnem = GetMnem(prevInstLocation)
    prev_inst_mnem = cleanMnem(prev_inst_mnem)
    if prev_inst_mnem in INST_JUMP:
        oldCmt = getOldComment(prevInstLocation)
        if oldCmt and FUNC_PREFIX in oldCmt and RTN_PREFIX not in oldCmt:
            return True
    return False


def cmtFuncReturn(instLocation):
    oldCmt = getOldComment(instLocation)
    if oldCmt and FUNC_PREFIX in oldCmt and RTN_PREFIX not in oldCmt:
        oldCmt += "\r\n" + RTN_PREFIX + "\r\n"
        i=0
        R_value = GetRegValue("R"+str(i))
        R_str = "R"+str(i)+"="+hex(R_value).replace("L","")+"="+str(R_value)
        R_MemList = getMemLinkedList(R_value)
        R_MemStrList = getMemLinkedStrList(R_MemList)
        strAppend = ""
        if R_MemStrList and len(R_MemStrList) > 1:
            for aMemStr in R_MemStrList:
                if aMemStr and len(aMemStr.strip())>0:
                    strAppend+=aMemStr + " -> "
        R_str = R_str + " : " + strAppend
        oldCmt += R_str +"\r\n"
        oldCmt += FUNC_PREFIX + '-'*20

        MakeComm(instLocation,oldCmt)


def analyzeInst(instLocation):
    inst = GetDisasm(instLocation)
    inst_mnem = GetMnem(instLocation)
    inst_mnem = cleanMnem(inst_mnem)

    updateSymbolDict(instLocation)

    #print inst

    opndList = []

    i = 0

    opnd = GetOpnd(instLocation,i)
    while opnd and len(opnd)>0:
        opndList.append(opnd)
        i+=1
        opnd = GetOpnd(instLocation,i)

    #1. function parameters
    if inst_mnem in INST_JUMP:
        cmtFuncParameters(instLocation,inst_mnem)
    #2. function return value
    if isPrevInstJmp(instLocation):
        prevInstLocation = getPrevInstLocation(instLocation)
        cmtFuncReturn(prevInstLocation)
    #3. String pointer comment and Hash function recognition
    srcData = getSourceData(inst_mnem,opndList)
    #print 'srcData:'+ hex(srcData)
    if not srcData or srcData<0x1000:
        return
    memList = getMemLinkedList(srcData)
    if not memList:
        #print "memList: None"
        return
    #print "memList:",[hex(x)[0:-1] for x in memList]
    cmtStr=addComments(memList)
    #print "cmtStr",cmtStr
    if cmtStr:
        addComment(instLocation,cmtStr)


def myStepOver():
    #
    pc_value = GetRegValue("pc")
    # cmt_str = GetCommentEx(pc_value,0)
    # """:type cmt_str str"""
    # analyzed = False
    # if cmt_str:
    #     cmt_str = cmt_str.strip()
    #     if len(cmt_str) > 0:
    #         if cmt_str.startswith(STR_PREFIX):
    #             analyzed = True
    # else:
    #     cmt_str = ""
    # if not analyzed:
    try:
        analyzeInst(pc_value)
    except Exception as e:
        traceback.print_exc()
        print e
    request_step_over()
    run_requests()

def myStepInto():
    pc_value = GetRegValue("pc")
    analyzeInst(pc_value)
    try:
        request_step_into() # causes internal error 40396 on version before 6.8
        run_requests()
    except Exception as e:
        traceback.print_exc()
        print e.message
def process():
    #print '[process]: start'

    # dbgStrCmtor = DbgStrCmtor()
    # dbgStrCmtor.hook()
    idaapi.add_hotkey("`+1",myStepInto)
    idaapi.add_hotkey("`+2",myStepOver)

    #print '[process]: done'


def finish():
    #print "[finish]: ..."
    pass


def main():
    #print '__main__ start'
    init()
    process()
    finish()
    #print '__main__ done'


if __name__=="__main__":
     main()

class DbgStrCmtorPlugin(idaapi.plugin_t):
    flags=idaapi.PLUGIN_KEEP
    comment="string commenter and encrypt function recognition"

    help = "dbgStrCmtor: \r\n Author: Simon Huang \r\n Email: thelongestusernameofall#gmail.com\r\n"
    wanted_name = "dbgStrCmtor"
    wanted_hotkey = "Alt-2"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self,arg):
        main()
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DbgStrCmtorPlugin()
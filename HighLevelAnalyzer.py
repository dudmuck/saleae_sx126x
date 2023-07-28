# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
# for SX126x

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import ctypes
from enum import Enum
c_uint8 = ctypes.c_uint8


class PacketType(Enum):
    NONE = 0 
    LORA = 1,
    FSK = 2,
    FHSS = 3

class Status_bits( ctypes.LittleEndianStructure ):
    _fields_ = [
                ("res0",      c_uint8, 1 ),  # 
                ("cmdStatus", c_uint8, 3 ),  # 
                ("chipMode",  c_uint8, 3 ),  # 
                ("res7",      c_uint8, 1 ),  # 
               ]

class Status( ctypes.Union ):
     _anonymous_ = ("bit",)
     _fields_ = [
                 ("bit",    Status_bits ),
                 ("asByte", c_uint8    )
                ]

# #define US_TO_SEMTEC_TICKS(X)                       (((X) * SEMTECH_TUS_IN_MSEC)/US_IN_MSEC)
# #define US_TO_SEMTEC_TICKS(X)                       (((X) * 64                 )/1000      )

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    fsk_bwDict = {
        0x1f: 4800,
        0x17: 5800,
        0x0f: 7300,
        0x1e: 9700,
        0x16: 11700,
        0x0e: 14600,
        0x1d: 19500,
        0x15: 23400,
        0x0d: 29300,
        0x1c: 39000,
        0x14: 46900,
        0x0c: 58600,
        0x1b: 78200,
        0x13: 93800,
        0x0b: 117300,
        0x1a: 156200,
        0x12: 187200,
        0x0a: 234300,
        0x19: 312000,
        0x11: 373600,
        0x09: 476000,
    }

    regDict = {
        0x6c0: 'SyncWord',
        0x736: 'IQInvert',  # fix for inverted IQ at bit 2
        0x740: 'LoRaSync', # LoRa Config22
        0x889: 'SdCfg0',
        0x8ac: 'AgcSensiAdj',
        0x8e7: 'paImax',
        0x911: 'XTAtrim',
        0x912: 'XTBtrim',
    }

    lora_bws = {
        0x00: 7.81,
        0x08: 10.42,
        0x01: 15.63,
        0x09: 20.8,
        0x02: 31.25,
        0x0a: 41.67,
        0x03: 62.5,
        0x04: 125,
        0x05: 250,
        0x06: 500,
    }

    def parseStatus(self, arg):
        status = Status()
        status.asByte = arg
        if status.chipMode == 2:
            chipMode = 'STBY_RC'
        elif status.chipMode == 3:
            chipMode = 'STBY_XOSC'
        elif status.chipMode == 4:
            chipMode = 'FS'
        elif status.chipMode == 5:
            chipMode = 'RX'
        elif status.chipMode == 6:
            chipMode = 'TX'
        else:
            chipMode = str(status.chipMode)

        if status.cmdStatus == 2:
            cmdStatus = 'dataAvail'
        elif status.cmdStatus == 3:
            cmdStatus = 'cmdTimeout'
        elif status.cmdStatus == 4:
            cmdStatus = 'cmdErr'
        elif status.cmdStatus == 5:
            cmdStatus = 'fail'
        elif status.cmdStatus == 6:
            cmdStatus = 'cmdTxDone'
        else:
            cmdStatus = str(status.cmdStatus)

        return '(' + chipMode + ' ' + cmdStatus + ')'

    def SetModulationParams(self):
        if self.pt == PacketType.FSK:
            br = int.from_bytes(bytearray(self.ba_mosi[1:4]), 'big')
            bps = 32 * 32000000 / br
            my_str = str(bps) + 'bps '
            pulseShape = self.ba_mosi[4]
            if pulseShape == 0:
                my_str = my_str + 'noFilter'
            elif pulseShape == 8:
                my_str = my_str + 'BT 0.3'
            elif pulseShape == 9:
                my_str = my_str + 'BT 0.5'
            elif pulseShape == 0x0a:
                my_str = my_str + 'BT 0.7'
            elif pulseShape == 0x0b:
                my_str = my_str + 'BT 1.0'
            else:
                my_str = my_str + hex(pulseShape)
            try:
                bw = self.fsk_bwDict[self.ba_mosi[5]]
                my_str = my_str + ' ' + str(bw) + 'Hz '
            except Exception as error:
                my_str = my_str + ' BW(' + hex(self.ba_mosi[5]) + ' ' + str(error) + ') '
            fdev = int.from_bytes(bytearray(self.ba_mosi[6:9]), 'big')
            my_str = my_str + ' ' + str(fdev) # + hex(fdev)
        elif self.pt == PacketType.LORA:
            sf = self.ba_mosi[1]
            my_str = 'SF' + str(sf)
            bw = self.ba_mosi[2]
            my_str = my_str + ' bw ' + str(self.lora_bws[bw]) + 'KHz'
            cr = self.ba_mosi[3]
            if cr == 1:
                crStr = '4/5'
            elif cr == 2:
                crStr = '4/6'
            elif cr == 3:
                crStr = '4/7'
            elif cr == 4:
                crStr = '4/8'
            else:
                crStr = hex(cr)
            my_str = my_str + ' CR' + crStr
            ldro = self.ba_mosi[4]
            if ldro == 0:
                ldroStr = 'OFF'
            elif ldro == 1:
                ldroStr = 'ON'
            else:
                ldroStr = hex(ldro)
            my_str = my_str + ' LDRO ' + ldroStr
        else:
            my_str = 'TODO pktType ' + str(self.pt)

        return 'SetModulationParams ' + my_str

    def SetPacketParams(self):
        if self.pt == PacketType.FSK:
            preambleLength = int.from_bytes(bytearray(self.ba_mosi[1:3]), 'big')
            my_str = 'preamble TX ' + str(preambleLength)
            detect = self.ba_mosi[3]
            if detect == 0:
                n_bits = 'OFF'
            elif detect == 4:
                n_bits = '8'
            elif detect == 5:
                n_bits = '16 '
            elif detect == 6:
                n_bits = '24'
            elif detect == 7:
                n_bits = '32'
            else:
                n_bits = '?'
            my_str = my_str + ' detect ' + n_bits + 'bits '

            syncWordBits = self.ba_mosi[4]
            my_str = my_str + ' syncWord ' + str(syncWordBits) + 'bits '

            addrComp = self.ba_mosi[5]
            if addrComp == 0:
                addrFilt = 'OFF'
            elif addrComp == 1:
                addrFilt = 'node'
            elif addrComp == 2:
                addrFilt = 'node & bcast'
            else:
                addrFilt = '?'
            my_str = my_str + ' addrFilt ' + addrFilt

            varLen = self.ba_mosi[6]
            if varLen == 0:
                my_str = my_str + ' fixLen'
            else:
                my_str = my_str + ' varLen'

            payLen = self.ba_mosi[7]
            my_str = my_str + ' payLen ' + str(payLen )

            crcType = self.ba_mosi[8]
            if crcType == 1:
                crc = 'OFF'
            elif crcType == 0:
                crc = '1_BYTE'
            elif crcType == 2:
                crc = '2_BYTE'
            elif crcType == 4:
                crc = '1_BYTE_INV'
            elif crcType == 6:
                crc = '2_BYTE_INV'
            else:
                crc = hex(crcType)
            my_str = my_str + ' CRC ' + str(crc)
        elif self.pt == PacketType.LORA:
            preambleLength = int.from_bytes(bytearray(self.ba_mosi[1:3]), 'big')
            my_str = 'preamble ' + str(preambleLength)
            headerType = self.ba_mosi[3]
            if headerType == 0:
                hdrStr = 'varLen'
            elif headerType == 1:
                hdrStr = 'fixrLen'
            else:
                hdrStr = hex(headerType)
            my_str = my_str + ' header ' + hdrStr
            payLen = self.ba_mosi[4]
            my_str = my_str + ' payLen' + str(payLen)
            crcOn = self.ba_mosi[5]
            if crcOn == 0:
                crcStr = 'ON'
            elif crcOn == 1:
                crcStr = 'OFF'
            else:
                crcStr = hex(crcOn)
            my_str = my_str + ' CRC_' + crcStr
            iqInv= self.ba_mosi[6]
            if iqInv == 0:
                iqStr = 'STD'
            elif iqInv == 1:
                iqStr = 'INV'
            else:
                iqStr = hex(iqInv)
            my_str = my_str + ' IQ ' + iqStr
        else:
            my_str = 'TODO pktType ' + str(self.pt)

        return 'SetPacketParams ' + my_str

    def SetRfFrequency(self):
        frf = int.from_bytes(bytearray(self.ba_mosi[1:5]), 'big')
        return 'SetRfFrequency ' + str(frf)

    def SetCadParams(self):
        cadSymbolNum = self.ba_mosi[1]
        cadDetPeak = self.ba_mosi[2]
        cadDetMin = self.ba_mosi[3]
        cadExitMode = self.ba_mosi[4]
        cadTimeout = int.from_bytes(bytearray(self.ba_mosi[5:7]), 'big')
        if cadExitMode == 0:
            exitStr = 'CAD_ONLY'
        elif cadExitMode == 1:
            exitStr = 'CAD_RX'
        else:
            exitStr = hex(cadExitMode)
        return 'SetCadParams cadSymbolNum ' + str(1<<cadSymbolNum) + ', cadDetPeak ' + str(cadDetPeak) + ', cadDetMin ' + str(cadDetMin) + ', exit ' + exitStr + ', timeout ' + hex(cadTimeout)

    def SetPacketType(self):
        if self.ba_mosi[1] == 0:
            self.pt = PacketType.FSK
            my_str = 'FSK'
        elif self.ba_mosi[1] == 1:
            self.pt = PacketType.LORA
            my_str = 'LoRa'
        elif self.ba_mosi[1] == 3:
            self.pt = PacketType.FHSS
            my_str = 'FHSS'
        else:
            self.pt = PacketType.NONE
            my_str = str(self.ba_mosi[1])
        return 'SetPacketType ' + my_str

    def GetIrqStatus(self):
        irqFlags = int.from_bytes(bytearray(self.ba_miso[2:4]), 'big')
        return 'GetIrqStatus ' + hex(irqFlags)

    def ClearIrqStatus(self):
        ClearIrqParam = int.from_bytes(bytearray(self.ba_mosi[1:3]), 'big')
        return 'ClearIrqStatus ' + hex(ClearIrqParam) #+ ' ' + fooStr

    def ReadRegister(self):
        addr = int.from_bytes(bytearray(self.ba_mosi[1:3]), 'big')
        array_alpha = self.ba_miso[4:]
        data_str = ''.join('{:02x}'.format(x) for x in array_alpha)
        try:
            regStr = self.regDict[addr]
        except Exception as error:
            regStr = hex(addr) + ' '  + str(error)
        return 'ReadRegister ' + regStr + ' --> ' + data_str

    def WriteRegister(self):
        addr = int.from_bytes(bytearray(self.ba_mosi[1:3]), 'big')
        array_alpha = self.ba_mosi[3:]
        data_str = ''.join('{:02x}'.format(x) for x in array_alpha)
        try:
            regStr = self.regDict[addr]
        except Exception as error:
            regStr = hex(addr) + ' '  + str(error)
        return 'WriteRegister ' + regStr + " <-- " + data_str

    def SetDioIrqParams(self):
        irqMask = int.from_bytes(bytearray(self.ba_mosi[1:3]), 'big')
        dio1_mask = int.from_bytes(bytearray(self.ba_mosi[3:5]), 'big')
        dio2_mask = int.from_bytes(bytearray(self.ba_mosi[5:7]), 'big')
        dio3_mask = int.from_bytes(bytearray(self.ba_mosi[7:9]), 'big')
        return 'SetDioIrqParams ' + hex(irqMask) + ' DIO1 ' + hex(dio1_mask) + ' DIO2 ' + hex(dio2_mask) + ' DIO3 ' + hex(dio3_mask) 

    def SetStandby(self):
        if self.ba_mosi[1] == 0:
            cfg = 'STDBY_RC'
        elif self.ba_mosi[1] == 1:
            cfg = 'STDBY_XOSC'
        else:
            cfg = hex(self.ba_mosi[1])
        return 'SetStandby ' + cfg

    def SetRx(self):
        timeout = int.from_bytes(bytearray(self.ba_mosi[1:4]), 'big')
        if timeout == 0xffffff:
            _str = 'continuous'
        elif timeout == 0:
            _str = 'single'
        else:
            us = (timeout * 1000) / 64
            _str = str(us) + 'μs'
        return 'SetRx ' + _str

    def SetSleep(self):
        return 'SetSleep'

    def StopTimerOnPreamble(self):
        en = self.ba_mosi[1]
        if en == 0:
            descr = 'stop on sync or header'
        elif en == 1:
            descr = 'stop on preamble'
        else:
            descr = hex(en)
        return 'StopTimerOnPreamble ' + descr

    def SetTxParams(self):
        txp = self.ba_mosi[1]
        if txp > 127:
            dBm = txp - 256
        else:
            dBm = txp
        ramp = self.ba_mosi[2]
        if ramp == 0:
            us = 10
        elif ramp == 1:
            us = 20
        elif ramp == 2:
            us = 40
        elif ramp == 3:
            us = 80
        elif ramp == 4:
            us = 200
        elif ramp == 5:
            us = 800
        elif ramp == 6:
            us = 1700
        elif ramp == 7:
            us = 3400
        else:
            us = 0 # ?
        return 'SetTxParams ' + str(dBm) + 'dBm' + ' ramp ' + str(us) + 'μs'

    def SetBufferBaseAddress(self):
        return 'SetBufferBaseAddress TX=' + hex(self.ba_mosi[1]) + ' RX=' + hex(self.ba_mosi[2])

    def CalImg(self):
        freq1 = self.ba_mosi[1]
        if freq1 == 0x68:
            str1 = '430-440'
        elif freq1 == 0x75:
            str1 = '470-510'
        elif freq1 == 0xc1:
            str1 = '779-787'
        elif freq1 == 0xd7:
            str1 = '863-870'
        elif freq1 == 0xe1:
            str1 = '902-928'
        else:
            str1 = hex(freq1)
        freq2 = self.ba_mosi[2]
        if freq2 == 0x6f:
            str2 = '430-440'
        elif freq2 == 0x81:
            str2 = '470-510'
        elif freq2 == 0xc5:
            str2 = '779-787'
        elif freq2 == 0xd8:
            str2 = '863-870'
        elif freq2 == 0xe9:
            str2 = '902-928'
        else:
            str2 = hex(freq2)
        return 'CalImg ' + str(str1) + ' ' + str(str2)

    def SetPaConfig(self):
        paDuty = self.ba_mosi[1]
        hpMax = self.ba_mosi[2]
        self.devSel = self.ba_mosi[3]
        if self.devSel == 0:
            devStr = 'SX1262'
        elif self.devSel == 1:
            devStr = 'SX1261'
        else:
            devStr = str(self.devSel)
        paLut = self.ba_mosi[4]
        return 'SetPaConfig paDuty ' + str(paDuty) + ' hpMax ' + str(hpMax) + ' ' + devStr + ' ' + str(paLut)

    def SetRegulatorMode(self):
        en = self.ba_mosi[1]
        if en == 0:
            my_str = 'LDO'
        elif en == 1:
            my_str = 'DC-DC'
        else:
            my_str = hex(en)
        return 'SetRegulatorMode ' + my_str

    def SetDIO2AsRfSwitchCtrl(self):
        en = self.ba_mosi[1]
        if en == 0:
            my_str = 'OFF'
        elif en == 1:
            my_str = 'ON'
        else:
            my_str = hex(en)
        return 'SetDIO2AsRfSwitchCtrl ' + my_str

    def SetLoRaSymbNumTimeout(self):
        return 'SetLoRaSymbNumTimeout ' + str(self.ba_mosi[1])

    myDict = {
        0x02: ClearIrqStatus,
        0x08: SetDioIrqParams,
        0x0d: WriteRegister,
        0x1d: ReadRegister,
        0x12: GetIrqStatus,
        0x80: SetStandby,
        0x82: SetRx,
        0x84: SetSleep,
        0x86: SetRfFrequency,
        0x88: SetCadParams,
        0x8a: SetPacketType,
        0x8b: SetModulationParams,
        0x8c: SetPacketParams,
        0x8e: SetTxParams,
        0x8f: SetBufferBaseAddress,
        0x95: SetPaConfig,
        0x98: CalImg,
        0x96: SetRegulatorMode,
        0x9d: SetDIO2AsRfSwitchCtrl,
        0x9f: StopTimerOnPreamble,
        0xa0: SetLoRaSymbNumTimeout,
    }

    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        },
        'match': { 'format': '{{data.string}}'}
    }

    def __init__(self):
        self.idx = 0
        self.pt = PacketType.NONE

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'result':
            if self.idx == 0:
                self.ba_mosi = frame.data['mosi']
                self.ba_miso = frame.data['miso']
            else:
                self.ba_mosi += frame.data['mosi']
                self.ba_miso += frame.data['miso']
            self.idx += 1
        elif frame.type == 'enable':   # falling edge of nSS
            self.ba_mosi = b'\x00'
            self.ba_miso = b'\x00'
            self.nss_fall_time = frame.start_time
            self.idx = 0
        elif frame.type == 'disable':   # rising edge of nSS
            self.idx = -1
            if len(self.ba_mosi) > 0:
                try:
                    my_str = self.myDict[self.ba_mosi[0]](self)
                except Exception as error:
                    if self.ba_mosi[0] == 0:
                        my_str = str(frame.end_time - self.nss_fall_time)
                    else:
                        my_str = hex(self.ba_mosi[0]) + ', error:' + str(error)

                if len(self.ba_mosi) > 1:
                    my_str = my_str + ' ' + self.parseStatus(self.ba_miso[1])
                print('--> ', my_str)
                return AnalyzerFrame('match', self.nss_fall_time, frame.end_time, {'string':my_str})
            else:
                print('--> zeroLength <--')
                return AnalyzerFrame('match', self.nss_fall_time, frame.end_time, {'string':'?? wake ??'})
        elif frame.type == 'error':
            print('error');


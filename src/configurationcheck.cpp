#include "configurationCheck.h"

#include "systemendianess.h"
#include <QString>
#include <QtDebug>
#include <QApplication>
#include <QFile>
#include <QDir>
#include <QDirIterator>
#include <QXmlStreamReader>
#include <QXmlStreamWriter>


//------------------------------------------------------------------------------
// union ConfigurationCheck::IPValue implementation
//------------------------------------------------------------------------------
// Accessors
//------------------------------------------------------------------------------
QString ConfigurationCheck::IPValue::toString()const{
    QString value;
    for(unsigned i=0;i<4;++i){
        value += QString::number(_fields[SystemEndianess::bigEndian() ? i : 3-i]);
        if(i<3)
            value += '.';
    }
    return value;
}
//------------------------------------------------------------------------------
// Operators
//------------------------------------------------------------------------------
ConfigurationCheck::IPValue& ConfigurationCheck::IPValue::operator=(int32_t rhs)
{
    _addr=rhs;
    return *this;
}
//------------------------------------------------------------------------------
ConfigurationCheck::IPValue& ConfigurationCheck::IPValue::operator=(
    const QString& ipLikeString)
{
    assign(ipLikeString);
    return *this;
}
//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------
void ConfigurationCheck::IPValue::assign(const QString& ipLikeString){
    _addr = 0;
    QStringList fields = ipLikeString.split(".");
    if(fields.size()==4){
        bool ok;
        for(int i=0;i<4;++i){
            uint field = fields[i].toUInt(&ok);
            if(!ok || field>255){
                _addr = 0;
                return;
            }
            _fields[SystemEndianess::bigEndian() ? i : 3-i] = uchar(field);
        }
    }
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// class ConfigurationCheck::IPPort implementation
//------------------------------------------------------------------------------
// Accessors
//------------------------------------------------------------------------------
QString ConfigurationCheck::IPPort::toXmlCodedString()const {
    return QString::number((_port << 16) + 1);
}
//------------------------------------------------------------------------------
// Operators
//------------------------------------------------------------------------------
ConfigurationCheck::IPPort& ConfigurationCheck::IPPort::operator=(
    uint32_t value)
{
    _port = value;
    if(_port>65535)
        _port = 0;
    return *this;
}
//------------------------------------------------------------------------------
ConfigurationCheck::IPPort& ConfigurationCheck::IPPort::operator=(
    const QString& xmlCodedValue)
{
    assign(xmlCodedValue);
    return *this;
}
//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------
void ConfigurationCheck::IPPort::assign(const QString& xmlCodedValue){
    _port = (xmlCodedValue.toUInt() & 0xFFFF0000) >> 16;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// class ConfigurationCheck::ProbeParameterDef implementation
//------------------------------------------------------------------------------
// Operators
//------------------------------------------------------------------------------
ConfigurationCheck::ProbeParameterDef& ConfigurationCheck::ProbeParameterDef::operator=(
    const ProbeParameterDef& rhs)
{
    which = rhs.which;
    rhs.name = rhs.name;
    return *this;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
// class ConfigurationCheck implementation
//------------------------------------------------------------------------------
// Static data
//------------------------------------------------------------------------------
typedef ConfigurationCheck CC_t;

const QString CC_t::_csvFilename = "Exprivia Mira probes configurations V2.1.csv";
CC_t::CSVField CC_t::_csvFields[] = {
    {"MIRA SN"          , -1 },
    {"PROBE IP"         , -1 },
    {"SUBNET MASK"      , -1 },
    {"GATEWAY"          , -1 },
    {"Central 0 IP"     , -1 },
    {"Central 0 SNTP"   , -1 },
    {"Global NTP List"  , -1 },
    {"New Updater IP"   , -1 }
};

const CC_t::CSVField& CC_t::_csvHeaderProbeSN = CC_t::_csvFields[0];
const CC_t::CSVField& CC_t::_csvHeaderProbeIP = CC_t::_csvFields[1];
const CC_t::CSVField& CC_t::_csvHeaderProbeNetMask = CC_t::_csvFields[2];
const CC_t::CSVField& CC_t::_csvHeaderProbeGateway = CC_t::_csvFields[3];
const CC_t::CSVField& CC_t::_csvHeaderProbeCentral0IP = CC_t::_csvFields[4];
const CC_t::CSVField& CC_t::_csvHeaderProbeCentral0SNTP = CC_t::_csvFields[5];
const CC_t::CSVField& CC_t::_csvHeaderProbeGlobalSNTP = CC_t::_csvFields[6];
const CC_t::CSVField& CC_t::_csvHeaderProbeNewUpdaterIP = CC_t::_csvFields[7];

const QString CC_t::_inputFirmwareVersion   = "1.5.6";
const QString CC_t::_outputFirmwareVersion  = "1.5.6";
//------------------------------------------------------------------------------
// Constructor
//------------------------------------------------------------------------------
ConfigurationCheck::ConfigurationCheck(QObject *parent) : QThread(parent),
    _stop(false),_processedConfigCount(0),
    _noCorrespondingExpriviaProbeConfigurationCount(0),
    _invalidEnvinetProbeSerialDirCount(0),_processingFailureCount(0),
    _modifiedConfigCount(0)
{
    _rootPath = qApp->applicationDirPath() + "/../../";
    if(!QFile::exists(_rootPath+"src/qMiraProbeXMLCheck.pro")){
        _rootPath += "../";
        if(!QFile::exists(_rootPath+"src/qMiraProbeXMLCheck.pro")){
            _rootPath = "";
            return;
        }
    }

    // set up XML checks
    _checks.insert("ConfigurationEntries(*)/Category(System)/Entry(SerialNr)",
                   ProbeParameterDef(ppSerialNr,"SerialNr"));
    _checks.insert("ConfigurationEntries(*)/Category(System)/Entry(StationId)",
                   ProbeParameterDef(ppStationId,"StationId"));
    _checks.insert("ConfigurationEntries(*)/Category(Devices)/Category(Ethernet)/Entry(UseDHCP)",
                   ProbeParameterDef(ppUseDHCP,"UseDHCP"));
    _checks.insert("ConfigurationEntries(*)/Category(Devices)/Category(Ethernet)/Entry(StaticIp)/Element(Ip Address)",
                   ProbeParameterDef(ppIpAddress,"Ip Address"));
    _checks.insert("ConfigurationEntries(*)/Category(Devices)/Category(Ethernet)/Entry(StaticIp)/Element(Subnet Mask)",
                   ProbeParameterDef(ppSubnetMask,"Subnet Mask"));
    _checks.insert("ConfigurationEntries(*)/Category(Devices)/Category(Ethernet)/Entry(StaticIp)/Element(Gateway)",
                   ProbeParameterDef(ppGateway,"Gateway"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Entry(Time Servers)/Element(Time Server 0)",
                   ProbeParameterDef(ppTimeServer0,"Time Server 0"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Entry(Time Servers)/Element(Time Server 1)",
                   ProbeParameterDef(ppTimeServer1,"Time Server 1"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Entry(Time Servers)/Element(Time Server 2)",
                   ProbeParameterDef(ppTimeServer2,"Time Server 2"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Entry(Time Servers)/Element(Time Server 3)",
                   ProbeParameterDef(ppTimeServer3,"Time Server 3"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 0)/Entry(Enable)",
                   ProbeParameterDef(ppCentral0Enable,"Central 0 Enable"));
#ifdef EXPRIVIA_CHECK_TIME_INTERVALS
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 0)/Entry(Communication Time)/Element(Repeat Base)",
                   ProbeParameterDef(ppCentral0RepeatBase,"Central 0 Repeat Base"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 0)/Entry(Communication Time)/Element(Repeat On Success)",
                   ProbeParameterDef(ppCentral0RepeatOnSuccess,"Central 0 Repeat On Success"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 0)/Entry(Communication Time)/Element(Repeat On Failure)",
                   ProbeParameterDef(ppCentral0RepeatOnFailure,"Central 0 Repeat On Failure"));
#endif
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 0)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: Port / Serial: Address High)",
                   ProbeParameterDef(ppCentral0Port,"Central 0 Port"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 0)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: IP Address / Serial: Address Low)",
                   ProbeParameterDef(ppCentral0IPAddress,"Central 0 IP Address"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 0)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: SNTP Server Ip / Serial: Destination Ip)",
                   ProbeParameterDef(ppCentral0SNTPServerIp,"Central 0 SNTP Server Ip"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 1)/Entry(Enable)",
                   ProbeParameterDef(ppCentral1Enable,"Central 1 Enable"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 2)/Entry(Enable)",
                   ProbeParameterDef(ppCentral2Enable,"Central 2 Enable"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 3)/Entry(Enable)",
                   ProbeParameterDef(ppCentral3Enable,"Central 3 Enable"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Central 4)/Entry(Enable)",
                   ProbeParameterDef(ppCentral4Enable,"Central 4 Enable"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Updater)/Entry(Communication Time)/Element(Repeat Base)",
                   ProbeParameterDef(ppUpdaterRepeatBase,"Updater Repeat Base"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Updater)/Entry(Communication Time)/Element(Repeat On Success)",
                   ProbeParameterDef(ppUpdaterRepeatOnSuccess,"Updater Repeat On Success"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Updater)/Entry(Communication Time)/Element(Repeat On Failure)",
                   ProbeParameterDef(ppUpdaterRepeatOnFailure,"Updater Repeat On Failure"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Updater)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: Port / Serial: Address High)",
                   ProbeParameterDef(ppUpdaterPort,"Updater Port"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Updater)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: IP Address / Serial: Address Low)",
                   ProbeParameterDef(ppUpdaterIPAddress,"Updater IP Address"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Updater)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: SNTP Server Ip / Serial: Destination Ip)",
                   ProbeParameterDef(ppUpdaterSNTPServerIp,"Updater SNTP Server Ip"));
#ifdef EXPRIVIA_CHECK_SERVICE_MODE
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Service Mode)/Entry(Communication Time)/Element(Repeat Base)",
                   ProbeParameterDef(ppServiceModeRepeatBase,"Service Mode Repeat Base"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Service Mode)/Entry(Communication Time)/Element(Repeat On Success)",
                   ProbeParameterDef(ppServiceModeRepeatOnSuccess,"Service Mode Repeat On Success"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Service Mode)/Entry(Communication Time)/Element(Repeat On Failure)",
                   ProbeParameterDef(ppServiceModeRepeatOnFailure,"Service Mode Repeat On Failure"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Service Mode)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: Port / Serial: Address High)",
                   ProbeParameterDef(ppServiceModePort,"Service Mode Port"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Service Mode)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: IP Address / Serial: Address Low)",
                   ProbeParameterDef(ppServiceModeIPAddress,"Service Mode IP Address"));
    _checks.insert("ConfigurationEntries(*)/Category(Communication)/Category(Central Connection Information)/Category(Special)/Category(Service Mode)/Entry(Device List)/Category(Device 0)/Element(TCP/IP: SNTP Server Ip / Serial: Destination Ip)",
                   ProbeParameterDef(ppServiceModeSNTPServerIp,"Service Mode SNTP Server Ip"));
#endif
}
//------------------------------------------------------------------------------
// Accessors
const QString& ConfigurationCheck::rootPath()const{
    return _rootPath;
}
//------------------------------------------------------------------------------
// Methods
void ConfigurationCheck::stop(){
    _stop = true;
}
//------------------------------------------------------------------------------
void ConfigurationCheck::run(){
    qInfo() << "Check starting.";

    try{
        if(_rootPath.length())
            qInfo() << "App path:" << _rootPath;
        else
            fatal("Cannot find expected directory tree project root.");

        QDir stationsCheckedDir(_rootPath+"modified_stations");
        if(stationsCheckedDir.exists() && !stationsCheckedDir.removeRecursively())
            fatal("Failed to remove target checked stations directory");

        qInfo() << "Begin reading Exprivia probe configurations";
        readConfigurationsFromCSV();
        qInfo() << "Reading Exprivia probe configurations done ("
                << _csvProbes.size() << " found).";
        if(!_csvProbes.size())
            fatal("No configured probes found.");

        _inputXmlFilename = QString::asprintf("ConfigV%sExpriviaN.xml",
                                         _inputFirmwareVersion.toUtf8().constData());
        _outputXmlFilename = QString::asprintf("ConfigV%sExpriviaN.xml",
                                         _outputFirmwareVersion.toUtf8().constData());
        checkProbeConfigurations();
    }catch(...)
    {
    }

    qInfo() << "Check done.";
}
//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------
void ConfigurationCheck::fatal(const QString& msg) const {
    qCritical(msg.toUtf8().constData());
    throw -1;
}
//------------------------------------------------------------------------------
bool ConfigurationCheck::readCSVRow(uint lineNum, QTextStream &in,
    QStringList& row)
{
    // vik: adapted from https://stackoverflow.com/questions/27318631/parsing-through-a-csv-file-in-qt

    static const int delta[][5] = {
        //  ,    "   \n    ?  eof
        {   1,   2,  -1,   0,  -1  }, // 0: parsing (store char)
        {   1,   2,  -1,   0,  -1  }, // 1: parsing (store column)
        {   3,   4,   3,   3,  -2  }, // 2: quote entered (no-op)
        {   3,   4,   3,   3,  -2  }, // 3: parsing inside quotes (store char)
        {   1,   3,  -1,   0,  -1  }, // 4: quote exited (no-op)
        // -1: end of row, store column, success
        // -2: eof inside quotes
    };

    row.clear();

    if (in.atEnd())
        return false;

    int state = 0, t = 0;
    char ch = 0;
    QString cell;

    while (state >= 0) {

        if (in.atEnd())
            t = 4;
        else {
            in >> ch;
            if (ch == ',') t = 0;
            else if (ch == '\"') t = 1;
            else if (ch == '\n') t = 2;
            else if(ch == '\r'){
                qint64 pos = in.pos();
                in >> ch;
                if(ch != '\n')
                    in.seek(pos);
            }
            else t = 3;
        }

        state = delta[state][t];

        switch (state) {
        case 0:
        case 3:
            cell += ch;
            break;
        case -1:
        case 1:
            row.append(cell);
            cell = "";
            break;
        }

    }

    if (state == -2)
        fatal(QString::asprintf("CSV line %d: End-of-file found while inside quotes.",
                                 lineNum));

    return true;
}
//------------------------------------------------------------------------------
void ConfigurationCheck::parseCSVHeaderLine(QStringList& row){
    const uint expectedFieldCount = sizeof(_csvFields)/sizeof(CSVField);
    uint fieldCount = 0;
    for(int i=0;i<row.size();++i){
        const QString& fieldName = row.at(i);
        for(uint j=0;j<expectedFieldCount;++j){
            CSVField& csvField = _csvFields[j];
            if(fieldName.simplified()==csvField.name){
                if(csvField.colNum==-1){
                    csvField.colNum = int(i);
                    fieldCount++;
                    break;
                }else
                    fatal(QString::asprintf("CSV header: duplicated column '%s'.",
                           fieldName.toUtf8().constData()));
            }
        }
    }

    if(expectedFieldCount!=fieldCount){
        qCritical() << "CSV header missing expected colums:";
        for(uint j=0;j<expectedFieldCount;++j)
            if(_csvFields[j].colNum==-1)
                qCritical() << QString::asprintf("    %s",_csvFields[j].name.toUtf8().constData());
        fatal("Bailing out");
    }
}
//------------------------------------------------------------------------------
void ConfigurationCheck::parseIPandPort(const QString& inIPAndPort,
    IPValue& outIPValue, IPPort& outPort)
{
    QStringList ipAndPort = inIPAndPort.split(":");
    if(ipAndPort.size()==2){
        outIPValue = ipAndPort.at(0);
        outPort = ipAndPort.at(1).toUInt();
    }
}
//------------------------------------------------------------------------------
void ConfigurationCheck::parseCSVProbeConfiguration(ProbeConfig& probeConfig,
    QStringList& row)
{
    probeConfig.serial = row.at(_csvHeaderProbeSN.colNum).toUInt();

    probeConfig.ip = row.at(_csvHeaderProbeIP.colNum);
    probeConfig.netmask = row.at(_csvHeaderProbeNetMask.colNum);
    probeConfig.gateway= row.at(_csvHeaderProbeGateway.colNum);
}
//------------------------------------------------------------------------------
void ConfigurationCheck::parseCSVSecondLine(ProbeConfig& probeConfig,
    QStringList& row)
{
    parseIPandPort(row.at(_csvHeaderProbeCentral0IP.colNum), _central0IP,
                   _central0Port);
    _central0SNTP = row.at(_csvHeaderProbeCentral0SNTP.colNum);
    _globalSNTP = row.at(_csvHeaderProbeGlobalSNTP.colNum);
    parseIPandPort(row.at(_csvHeaderProbeNewUpdaterIP.colNum), _newUpdaterIP,
                   _newUpdaterPort);

    parseCSVProbeConfiguration(probeConfig,row);
}
//------------------------------------------------------------------------------
void ConfigurationCheck::addProbeConfig(uint lineNum, ProbeConfig& probeConfig){
    if(!probeConfig.serial || probeConfig.serial<cMinProbeSerial ||
       probeConfig.serial>cMaxProbeSerial)
    {
        qCritical() << QString::asprintf("Probe at CSV line %d has no serial, skipped",
                                         lineNum);
        return;
    }

    bool skip = false;
    if(!probeConfig.ip && (skip=true))
        qCritical() << QString::asprintf("Probe %u (CSV line %d) has invalid IP, skipped",
                                         probeConfig.serial, lineNum);
    if(!probeConfig.netmask && (skip=true))
        qCritical() << QString::asprintf("Probe %u (CSV line %d) has invalid Netmask, skipped",
                                         probeConfig.serial, lineNum);
    if(!probeConfig.gateway && (skip=true))
        qCritical() << QString::asprintf("Probe %u (CSV line %d) has invalid Gateway, skipped",
                                         probeConfig.serial, lineNum);

    if(!skip)
        _csvProbes.insert(probeConfig.serial,probeConfig);
}
//------------------------------------------------------------------------------
void ConfigurationCheck::readConfigurationsFromCSV(){
    QFile csv(_rootPath+_csvFilename);
    if(!csv.open(QFile::ReadOnly | QFile::Text))
        fatal("Cannot open probe configuration CSV file");

    QTextStream in(&csv);
    QStringList row;

    if(readCSVRow(1, in, row)){
        parseCSVHeaderLine(row);

        uint lineNum = 2;
        if(readCSVRow(lineNum, in, row)){
            ProbeConfig probeConfig;
            parseCSVSecondLine(probeConfig,row);
            if(!_central0IP)
                fatal("Central0 IP not found or invalid");
            if(!_central0Port)
                fatal("Central0 port not found or invalid");
            if(!_central0SNTP)
                fatal("Central0 SNTP not found or invalid");
            if(!_globalSNTP)
                fatal("Global SNTP not found or invalid");
            if(!_newUpdaterIP)
                fatal("New updater server IP not found or invalid");
            if(!_newUpdaterPort)
                fatal("New updater server port not found or invalid");

            addProbeConfig(lineNum,probeConfig);

            while(!_stop && readCSVRow(++lineNum, in, row)){
                parseCSVProbeConfiguration(probeConfig,row);
                addProbeConfig(lineNum,probeConfig);
            }
        }
    }

    if(!_csvProbes.size())
        fatal("No probe configurations read from CSV file");
}
//------------------------------------------------------------------------------
bool ConfigurationCheck::checkProbeParameter(
    const ConfigurationCheck::ProbeConfig& probeConfig,
    const ConfigurationCheck::ProbeParameterDef& paramDef,QString& value)
{
    bool isIP = false;
    QString expectedValue;
    switch(paramDef.which){
        case ppSerialNr:
        case ppStationId:
            expectedValue = QString::number(probeConfig.serial);
            break;
        case ppUseDHCP:
            expectedValue = '0';
            break;
        case ppIpAddress:
            isIP = true;
            expectedValue = probeConfig.ip.toString();
            break;
        case ppSubnetMask:
            isIP = true;
            expectedValue = probeConfig.netmask.toString();
            break;
        case ppGateway:
            isIP = true;
            expectedValue = probeConfig.gateway.toString();
            break;
        case ppTimeServer0:
            isIP = true;
            expectedValue = _globalSNTP.toString();
            break;
        case ppTimeServer1:
            expectedValue = '0';
            break;
        case ppTimeServer2:
            expectedValue = '0';
            break;
        case ppTimeServer3:
            expectedValue = '0';
            break;
        case ppCentral0Enable:
            expectedValue = '1';
            break;
        case ppCentral0RepeatBase:
            expectedValue = "60";
            break;
        case ppCentral0RepeatOnSuccess:
            expectedValue = "60";
            break;
        case ppCentral0RepeatOnFailure:
            expectedValue = "60";
            break;
        case ppCentral0Port:
            expectedValue = _central0Port.toXmlCodedString();
            break;
        case ppCentral0IPAddress:
            isIP = true;
            expectedValue = _central0IP.toString();
            break;
        case ppCentral0SNTPServerIp:
            isIP = true;
            expectedValue = _central0SNTP.toString();
            break;
        case ppCentral1Enable:
            expectedValue = '0';
            break;
        case ppCentral2Enable:
            expectedValue = '0';
            break;
        case ppCentral3Enable:
            expectedValue = '0';
            break;
        case ppCentral4Enable:
            expectedValue = '0';
            break;
        case ppUpdaterRepeatBase:
        case ppServiceModeRepeatBase:
            expectedValue = "10";
            break;
        case ppUpdaterRepeatOnSuccess:
        case ppServiceModeRepeatOnSuccess:
            expectedValue = "20";
            break;
        case ppUpdaterRepeatOnFailure:
        case ppServiceModeRepeatOnFailure:
            expectedValue = "30";
            break;
        case ppUpdaterPort:
        case ppServiceModePort:
            expectedValue = _newUpdaterPort.toXmlCodedString();
            break;
        case ppUpdaterIPAddress:
        case ppServiceModeIPAddress:
            isIP = true;
            expectedValue = _newUpdaterIP.toString();
            break;
        case ppUpdaterSNTPServerIp:
        case ppServiceModeSNTPServerIp:
            isIP = true;
            expectedValue = _central0SNTP.toString();
            break;
         default: // Foresee future enum expansion: ignore warning!
            qCritical() << "Internal error: XML check unknown ProbeParameter";
            break;
    }

    QString ipValue = IPValue(value.toInt()).toString();
    bool dirty = isIP ? expectedValue!=ipValue : expectedValue!=value;
    if(dirty){
        qWarning() << "probe " << probeConfig.serial << " - Wrong"
                   << paramDef.name << ", expected: " << expectedValue
                   << " got:" << (isIP ? ipValue : value) << " (FIXING!)";
        value = isIP ? QString::number(IPValue(expectedValue).toInt32())
                     : expectedValue;
    }
    return dirty;
}
//------------------------------------------------------------------------------
void ConfigurationCheck::checkProbeConfiguration(const ProbeConfig& probeConfig)
{
    QString inFilename = _rootPath + "stations/" +
                         QString::number(probeConfig.serial) +
                         "/" + _inputXmlFilename;
    QFile inFile(inFilename);
    if(!inFile.open(QIODevice::ReadOnly)) {
        qInfo() << "Cannot open the Envinet station file " << inFile.fileName();
        ++_processingFailureCount;
        return;
    }
    QXmlStreamReader xmlReader;
    xmlReader.setDevice(&inFile);

    QString outFilename = _rootPath+"tmp.xml";
    QFile outFile(outFilename);
    if(!outFile.open(QIODevice::Truncate | QIODevice::WriteOnly |
                     QIODevice::Text)) {
        qInfo() << "Cannot open the temp station file " << outFile.fileName();
        ++_processingFailureCount;
        return;
    }
    QXmlStreamWriter xmlWriter(&outFile);
    xmlWriter.setDevice(&outFile);
    xmlWriter.setAutoFormatting(false);

    QStringList elementPathList;
    QString elementTag;
    QStringRef elementName;
    QXmlStreamAttributes attributes;
    QString elementPath;
    bool dirty = false;
    QString unimplemented;
    ProbeParameterDef *parameterToBeChecked = nullptr;
    int performedCheckCount = 0;
    QString characters;
    while(!xmlReader.atEnd()){
        QXmlStreamReader::TokenType	token = xmlReader.tokenType();
        switch(token){
            case QXmlStreamReader::NoToken:
                break;
            case QXmlStreamReader::Invalid:
                qInfo() << "Failure while parsing the station file "
                        << inFile.fileName() << " reason: "
                        << xmlReader.errorString();
                ++_processingFailureCount;
                return;
            case QXmlStreamReader::StartDocument:
                xmlWriter.setCodec(xmlReader.documentEncoding().toUtf8().constData());
                xmlWriter.writeStartDocument(xmlReader.documentVersion().toString(),
                                             xmlReader.isStandaloneDocument());
                break;
            case QXmlStreamReader::EndDocument:
                xmlWriter.writeEndDocument();
                break;
            case QXmlStreamReader::StartElement:
                elementTag = xmlReader.name().toString();
                xmlWriter.writeStartElement(elementTag);

                attributes = xmlReader.attributes();
                elementName = attributes.value("name");
                elementTag += '(' +
                              (elementName.isEmpty() ? "*"
                                                     : elementName.toString()) +
                               ')';
                elementPathList.append(elementTag);
                elementPath = elementPathList.join('/');

                //TBR qInfo() << elementPath;
                {
                QMap<ElementPath_t,ProbeParameterDef>::iterator it = _checks.find(elementPath);
                parameterToBeChecked = it!=_checks.end() ? &*it : nullptr;
                }

                xmlWriter.writeAttributes(attributes);
                break;
            case QXmlStreamReader::EndElement:
                xmlWriter.writeEndElement();
                elementPathList.removeLast();
                elementPath = elementPathList.join('/');
                //TBR qInfo() << elementPath;
                break;
            case QXmlStreamReader::Characters:
                if(xmlReader.isCDATA())
                    xmlWriter.writeDTD(xmlReader.text().toString());
                else{
                    characters = xmlReader.text().toString();
                    if(parameterToBeChecked){
                        dirty |= checkProbeParameter(probeConfig,
                                                     *parameterToBeChecked,
                                                     characters);
                        parameterToBeChecked=nullptr;
                        ++performedCheckCount;
                    }
                    xmlWriter.writeCharacters(characters);
                }
                break;
            case QXmlStreamReader::Comment:
                xmlWriter.writeComment(xmlReader.text().toString());
                break;
            //--------------------------
            // Unimplemented!
            //--------------------------
            case QXmlStreamReader::DTD:
                unimplemented = "DTD";
                break;
            case QXmlStreamReader::EntityReference:
                unimplemented = "EntityReference";
                break;
            case QXmlStreamReader::ProcessingInstruction:
                unimplemented = "ProcessingInstruction";
                break;
        }

        if(unimplemented.length()){
            qInfo() << "Failure while parsing the station file "
                    << inFile.fileName() << " unimplemented '"
                    << unimplemented << "' handling was requested!";
            ++_processingFailureCount;
            return;
        }

        xmlReader.readNext();
    }
    inFile.close();
    outFile.close();

    if(performedCheckCount!=_checks.size())
        qWarning() << "Not all due checks have been performed, probe "
                   << probeConfig.serial;

    if(dirty){
        QString dstDirPath = _rootPath + "modified_stations/" +
                             QString::number(probeConfig.serial)+"/";

        bool error;
        if((error = !QDir().mkpath(dstDirPath)))
            qCritical() << "Cannot create modified XML file directory '" <<
                           dstDirPath << "'.";

        if(!error &&
           (error = !QFile::rename(outFilename,dstDirPath+_outputXmlFilename)))
        {
            qCritical() << "Cannot create modified XML station file for probe"
                        << probeConfig.serial;
        }
        if(error)
            ++_processingFailureCount;
        else
            ++_modifiedConfigCount;
    }else
        QFile::remove(outFilename);
}
//------------------------------------------------------------------------------
void ConfigurationCheck::checkProbeConfigurations(){
    QDir stationsDir(_rootPath+"/stations");

    {
        QDirIterator it(stationsDir, QDirIterator::NoIteratorFlags);
        int itemCount = 0;
        while(!_stop && it.hasNext()) {
            ++itemCount;
            it.next();
        }
        emit setProgressRange(0,itemCount);
    }

    QDirIterator it(stationsDir, QDirIterator::NoIteratorFlags);
    bool ok;
    int currItem=0;
    while(!_stop && it.hasNext()) {
        it.next();

        QFileInfo fileInfo = it.fileInfo();
        //qDebug() << fileInfo.fileName();
        uint serial = fileInfo.fileName().toUInt(&ok);
        if(fileInfo.isDir() && ok){
            ++_processedConfigCount;

            if(serial>=cMinProbeSerial && serial<=cMaxProbeSerial){
                QMap<ProbeSerialNr_t,ProbeConfig>::iterator it2 = _csvProbes.find(serial);
                if(it2!=_csvProbes.end()){
                    it2->checked = true;
                    checkProbeConfiguration(*it2);
                }else{
                    qCritical() << QString::asprintf("Cannot check Envinet's "
                                   "configuration station file dir %d: corresponding "
                                   " Exprivia configuration not found.", serial);
                    ++_noCorrespondingExpriviaProbeConfigurationCount;
                }
            }else{
                qCritical() << QString::asprintf("Cannot check Envinet's "
                               "configuration station file dir %d: invalid "
                               " station serial.", serial);
                ++_invalidEnvinetProbeSerialDirCount;
            }
        }

        emit setProgressValue(++currItem);
    }

    QList<const ProbeConfig *> uncheckedConfigs;
    for(QMap<ProbeSerialNr_t,ProbeConfig>::iterator it=_csvProbes.begin();
        it!=_csvProbes.end();
        ++it)
    {
        if(!it->checked)
            uncheckedConfigs.push_back(&*it);
    }

    QString checkTimeIntervals, checkServiceMode;
#ifdef EXPRIVIA_CHECK_TIME_INTERVALS
    checkTimeIntervals = "ON";
#else
    checkTimeIntervals = "OFF";
#endif
#ifdef EXPRIVIA_CHECK_SERVICE_MODE
    checkServiceMode = "ON";
#else
    checkServiceMode = "OFF";
#endif

    qInfo() << "--------------------------------------------------------------------------------";
    qInfo() << "Summary";
    qInfo() << "--------------------------------------------------------------------------------";
    qInfo() << "Configuration switches";
    qInfo() << "    EXPRIVIA_CHECK_TIME_INTERVALS:" << checkTimeIntervals;
    qInfo() << "    EXPRIVIA_CHECK_SERVICE_MODE  :" << checkServiceMode;
    qInfo() << "XML filenames";
    qInfo() << "    input :" << _inputXmlFilename;
    qInfo() << "    output:" << _outputXmlFilename;
    qInfo() << "Total Envinet configurations (dir/file) processed:"
            << _processedConfigCount;
    qInfo() << "   Skipped because of invalid Envinet Probe Serial (dir name):"
            << _invalidEnvinetProbeSerialDirCount;
    qInfo() << "   Skipped because of no corresponding Exprivia configuration:"
            << _noCorrespondingExpriviaProbeConfigurationCount;
    qInfo() << "   Failed to parse/handle configuration XML file (please see reason above):"
            << _processingFailureCount;
    qInfo() << "   Fixed (failed parameters check) to corresponding dir/file in 'modified_stations':"
            << _modifiedConfigCount;
    if(uncheckedConfigs.size()){
        qInfo() << "Following exprivia configurations had no corresponding "
                   "Envinet station file configuration:";
        for(int i=0;i<uncheckedConfigs.size();++i)
            qInfo() << QString::asprintf("    %d", uncheckedConfigs.at(i)->serial);
    }
}
//------------------------------------------------------------------------------

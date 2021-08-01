#ifndef CONFIGURATIONCHECK_H
#define CONFIGURATIONCHECK_H

#include<QThread>
#include<QString>
#include<QTextStream>


//------------------------------------------------------------------------------
// class ConfigurationCheck
//------------------------------------------------------------------------------
class ConfigurationCheck : public QThread
{
    Q_OBJECT
    public:
        // Constructor
        ConfigurationCheck(QObject *parent = nullptr);
        // Accessors
        const QString& rootPath()const;
        // Methods
        void stop();
    protected:
        virtual void run();
    signals:
        void setProgressRange(int minimum, int maximum);
        void setProgressValue(int value);
    private:
        // Constants
        enum {
            cMinProbeSerial = 30000,
            cMaxProbeSerial = 30999,
        };
        // Types
        struct CSVField {
            const QString name;
            int colNum;
        };
        union IPValue {
            // Constructors
            inline IPValue() : _addr(0) {}
            inline IPValue(int32_t addr) : _addr(addr) {}
            inline IPValue(const QString& ipLikeString) { assign(ipLikeString); }
            // Accessors
            QString toString()const;
            inline int32_t toInt32()const { return _addr; }
            // Operators
            IPValue& operator=(int32_t rhs);
            IPValue& operator=(const QString& ipLikeString);
            inline operator bool()const { return _addr; }
            inline bool operator !()const { return !_addr; }
            /* TBR
            inline bool operator==(const IPValue& rhs)const { return addr==rhs.addr; }
            inline bool operator!=(const IPValue& rhs)const  { return addr!=rhs.addr; }
            */
        private:
            // Data
            int32_t _addr;
            uchar _fields[4];
            // Helpers
            void assign(const QString& ipLikeString);
        };
        class IPPort {
        public:
            // Constructors
            inline IPPort() : _port(0) {}
            inline IPPort(uint32_t port) : _port(port) {}
            inline IPPort(const IPPort& src) : _port(src._port) {}
            inline IPPort(const QString& xmlCodedValue) { assign(xmlCodedValue); }
            // Accessors
            QString toXmlCodedString()const;
            // Operators
            IPPort& operator=(uint32_t value);
            IPPort& operator=(const QString& xmlCodedValue);
            inline operator bool()const { return _port; }
            inline bool operator !()const { return !_port; }
        private:
            uint32_t _port;
            // Helpers
            void assign(const QString& xmlCodedValue);
        };
        struct ProbeConfig {
            inline ProbeConfig() : serial(0), checked(false) {}

            uint serial;
            IPValue ip;
            IPValue netmask;
            IPValue gateway;
            bool checked;
        };
        enum ProbeParameter {
            ppSerialNr,
            ppStationId,
            ppUseDHCP,
            ppIpAddress,
            ppSubnetMask,
            ppGateway,
            ppTimeServer0,
            ppTimeServer1,
            ppTimeServer2,
            ppTimeServer3,
            ppCentral0Enable,
            ppCentral0RepeatBase,
            ppCentral0RepeatOnSuccess,
            ppCentral0RepeatOnFailure,
            ppCentral0Port,
            ppCentral0IPAddress,
            ppCentral0SNTPServerIp,
            ppCentral1Enable,
            ppCentral2Enable,
            ppCentral3Enable,
            ppCentral4Enable,
            ppUpdaterRepeatBase,
            ppUpdaterRepeatOnSuccess,
            ppUpdaterRepeatOnFailure,
            ppUpdaterPort,
            ppUpdaterIPAddress,
            ppUpdaterSNTPServerIp,
            ppServiceModeRepeatBase,
            ppServiceModeRepeatOnSuccess,
            ppServiceModeRepeatOnFailure,
            ppServiceModePort,
            ppServiceModeIPAddress,
            ppServiceModeSNTPServerIp,
        };
        struct ProbeParameterDef {
            // Constructors
            inline ProbeParameterDef(ProbeParameter which_,
                              const QString& name_) :
                which(which_),name(name_)
            {
            }
            inline ProbeParameterDef(const ProbeParameterDef& src) :
                which(src.which),name(src.name)
            {
            }
            // Operators
            ProbeParameterDef& operator=(const ProbeParameterDef& rhs);
            // Public (const) data
            mutable ProbeParameter which;
            mutable QString name;
        };
        typedef uint ProbeSerialNr_t;
        typedef QString ElementPath_t;
        /* TBR
        typedef bool (ConfigurationCheck::* CheckFnPtr_t)(const ProbeConfig& probeConfig,
                                                          QString& text);
        */
        // Data
        static const QString _csvFilename;
        static CSVField _csvFields[];
        static const CSVField& _csvHeaderProbeSN;
        static const CSVField& _csvHeaderProbeIP;
        static const CSVField& _csvHeaderProbeNetMask;
        static const CSVField& _csvHeaderProbeGateway;
        static const CSVField& _csvHeaderProbeCentral0IP;
        static const CSVField& _csvHeaderProbeCentral0SNTP;
        static const CSVField& _csvHeaderProbeGlobalSNTP;
        static const CSVField& _csvHeaderProbeNewUpdaterIP;
        static const QString _inputFirmwareVersion;
        static const QString _outputFirmwareVersion;

        bool _stop; // no use to make it thread safe!
        QString _rootPath;
        //TBR QMap<ElementPath_t,CheckFnPtr_t> _checks;
        QMap<ElementPath_t,ProbeParameterDef> _checks;
        IPValue _central0IP;
        IPPort _central0Port;
        IPValue _central0SNTP;
        IPValue _globalSNTP;
        IPValue _newUpdaterIP;
        IPPort _newUpdaterPort;
        QMap<ProbeSerialNr_t,ProbeConfig> _csvProbes;
        QString _inputXmlFilename;
        QString _outputXmlFilename;
        uint _processedConfigCount;
        uint _noCorrespondingExpriviaProbeConfigurationCount;
        uint _invalidEnvinetProbeSerialDirCount;
        uint _processingFailureCount;
        uint _modifiedConfigCount;
        // Helpers
        [[ noreturn ]] void fatal(const QString& msg)const;
        bool readCSVRow(unsigned lineNum, QTextStream &in, QStringList& row);
        void parseCSVHeaderLine(QStringList& row);
        void parseIPandPort(const QString& inIPAndPort, IPValue& outIPValue,
                            IPPort& outPort);
        void parseCSVProbeConfiguration(ProbeConfig& probeConfig,
                                        QStringList& row);
        void parseCSVSecondLine(ProbeConfig& probeConfig, QStringList& row);
        void addProbeConfig(uint lineNum, ProbeConfig& probeConfig);
        void readConfigurationsFromCSV();
        bool checkProbeParameter(const ProbeConfig& probeConfig,
                                 const ProbeParameterDef& paramDef,
                                 QString& value);
        void checkProbeConfiguration(const ProbeConfig& probeConfig);
        void checkProbeConfigurations();
};

#endif // CONFIGURATIONCHECK_H

#include "mainWindow.h"
#include "ui_mainWindow.h"
#include <QLoggingCategory>
#include <QTextStream>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QProgressBar>
#include "configurationCheck.h"


//------------------------------------------------------------------------------
// class MainWindow implementation
//------------------------------------------------------------------------------
// Static data
//------------------------------------------------------------------------------
MainWindow * MainWindow::_mainWindow = nullptr;
QTextStream * MainWindow::_logStream = nullptr;
//------------------------------------------------------------------------------
// Constructor
//------------------------------------------------------------------------------
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
    _ui(new Ui::MainWindow),
    _configurationCheck(new ConfigurationCheck(this)),
    _logFile(_configurationCheck->rootPath().length()
             ? new QFile(_configurationCheck->rootPath()+"check.log",this)
             : nullptr)
{
    // needed to see log messages in QtCreator console!
    QLoggingCategory::defaultCategory()->setEnabled(QtDebugMsg, true);

    // Set up UI
    _ui->setupUi(this);
    _progressBar = new QProgressBar(_ui->statusBar);
    _progressBar->setRange(0,100);
    _progressBar->setValue(0);
    _progressBar->setTextVisible(false);
    _ui->statusBar->addPermanentWidget(_progressBar,1);

    // Set up logging
    if(!_logFile){
        fprintf(stderr, "Failed to detect rootPath.");
        ::abort();
    }else if(!_logFile->open(QIODevice::Truncate | QIODevice::WriteOnly)){
        fprintf(stderr, "Failed to open log file %s",
                _logFile->fileName().toUtf8().constData());
        ::abort();
    }
    _logStream = new QTextStream(_logFile);
    _mainWindow = this;
    connect(this, SIGNAL(addLogLine(QString)),
            _ui->teLog, SLOT(append(QString)));

    qInstallMessageHandler(messageOutputHandler);

    // Set up and start worker thread
    connect(_configurationCheck, SIGNAL(setProgressRange(int,int)),
            _progressBar, SLOT(setRange(int,int)));
    connect(_configurationCheck, SIGNAL(setProgressValue(int)),
            _progressBar, SLOT(setValue(int)));
    _configurationCheck->start();
}
//------------------------------------------------------------------------------
// Destructor
//------------------------------------------------------------------------------
MainWindow::~MainWindow() {
    _configurationCheck->stop();
    _configurationCheck->wait();

    _mainWindow = nullptr;

    _logStream->flush();
    delete _logStream;
    _logFile->close();

    delete _ui;
}
//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------
void MainWindow::messageOutputHandler(QtMsgType type,
    const QMessageLogContext &context, const QString &msg)
{
    static char msgBuff[1024];
    static const char * types[] = {
        "Debug   ",
        "Info    ",
        "Warning ",
        "Critical",
        "Fatal   "
    };
    static QMutex mutex;

    QMutexLocker lock(&mutex);

    QByteArray localMsg = msg.length() && msg.at(0)=='\"'
                          ? msg.midRef(1,msg.length()-2).toLocal8Bit()
                          : msg.toLocal8Bit();
    const char *typeStr;
    bool debug = false;
    switch (type) {
        case QtDebugMsg:
            typeStr = types[0];
            debug = true;
            break;
        case QtInfoMsg:
            typeStr = types[1];
            break;
        case QtWarningMsg:
            typeStr = types[2];
            break;
        case QtCriticalMsg:
            typeStr = types[3];
            break;
        case QtFatalMsg:
            typeStr = types[4];
            break;
        default:
            fprintf(stderr, "messageOutputHandler() internal error: unknown log type!");
            ::abort();
    }

    if(debug)
        sprintf(msgBuff, "%s: %s (%s:%u, %s)\n", typeStr,
                         localMsg.constData(), context.file,
                         context.line, context.function);
    else
        sprintf(msgBuff, "%s: %s\n", typeStr, localMsg.constData());
    msgBuff[sizeof(msgBuff)-1] = 0;

    fprintf(stderr, msgBuff);

    if(_mainWindow){
        *_logStream << msgBuff;
        _logStream->flush();

        size_t len = strlen(msgBuff);
        if(len)
            msgBuff[len-1] = 0;
        _mainWindow->logLine(msgBuff);
     }
}
//------------------------------------------------------------------------------
void MainWindow::logLine(const QString& msg){
    emit addLogLine(msg);
}
//------------------------------------------------------------------------------

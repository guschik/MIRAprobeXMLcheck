#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "configurationCheck.h"


//------------------------------------------------------------------------------
// Forwards
//------------------------------------------------------------------------------
namespace Ui {
    class MainWindow;
}
class QTextEdit;
class QProgressBar;
class QFile;
class QTextStream;


//------------------------------------------------------------------------------
// class MainWindow
//------------------------------------------------------------------------------
class MainWindow : public QMainWindow
{
    Q_OBJECT
    public:
        // Constructor
        explicit MainWindow(QWidget *parent = nullptr);
        // Destructor
        ~MainWindow();
    signals:
        void addLogLine(const QString& msg);
    private:
        // Data
        static MainWindow  *_mainWindow;
        static QTextStream *_logStream;

        Ui::MainWindow *_ui;
        ConfigurationCheck *_configurationCheck;
        QFile *_logFile;
        QProgressBar *_progressBar;
        // Helpers
        static void messageOutputHandler(QtMsgType type,
                                         const QMessageLogContext &context,
                                         const QString &msg);
        void logLine(const QString& msg);
};

#endif // MAINWINDOW_H

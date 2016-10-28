#pragma once

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include <cstdio>
#include <ctime>
#include <cassert>

#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <map>

// ARGH not thread-safe... LAM

typedef enum {
    EMERG = LOG_EMERG,
    ALERT = LOG_ALERT,
    CRIT = LOG_CRIT,
    ERROR = LOG_ERR,
    WARN = LOG_WARNING,
    NOTICE = LOG_NOTICE,
    INFO = LOG_INFO,
    DEBUG = LOG_DEBUG,
    NONE = LOG_DEBUG + 1,
} LogLevelE;

typedef std::pair<LogLevelE, std::string> LevelToNameT;
typedef std::pair<std::string, LogLevelE> NameToLevelT;
typedef std::map<LogLevelE, std::string> LevelToNameMapT;
typedef std::map<std::string, LogLevelE> NameToLevelMapT;

static LevelToNameT _levelToName[] =
{
    LevelToNameT(EMERG,  "EMERG "),
    LevelToNameT(ALERT,  "ALERT "),
    LevelToNameT(CRIT,   "CRIT  "),
    LevelToNameT(ERROR,  "ERROR "),
    LevelToNameT(WARN,   "WARN  "),
    LevelToNameT(NOTICE, "NOTE  "),
    LevelToNameT(INFO,   "INFO  "),
    LevelToNameT(DEBUG,  "DEBUG ")
};

static NameToLevelT _nameToLevel[] =
{
    NameToLevelT("emerg", EMERG),
    NameToLevelT("alert", ALERT),
    NameToLevelT("crit",  CRIT),
    NameToLevelT("error", ERROR),
    NameToLevelT("warn",  WARN),
    NameToLevelT("note",  NOTICE),
    NameToLevelT("info",  INFO),
    NameToLevelT("debug", DEBUG)
};

static LevelToNameMapT LevelToNameMap(_levelToName, _levelToName + sizeof(_levelToName) / sizeof(_levelToName[0]));
static NameToLevelMapT NameToLevelMap(_nameToLevel, _nameToLevel + sizeof(_nameToLevel) / sizeof(_nameToLevel[0]));

std::string timestamp();

class LogCollector {
public:
    LogCollector(const std::string& tag = ""):
    _tag(tag) {
        if (!_tag.empty()) {
            _tag += " ";
        }
    }

    virtual ~LogCollector() { }
    
    virtual int output() {
        std::cerr << _os.str() << std::endl;
        _os.str(std::string());
        return 0;
    }
    
    std::ostringstream& get(LogLevelE level = INFO) {
        _os << tag() << timestamp() << " " << level_string(level);
        return _os;
    }
    
    static std::string level_string(LogLevelE level) {
        return LevelToNameMap[level];
    }
    
    virtual int fd() { return STDERR_FILENO; }
    virtual void restart() { }

    virtual bool good() { return true; }
    
    const std::string& tag() const { return _tag; }

protected:
    std::ostringstream _os;
    std::string _tag;
};

class NullCollector: public LogCollector {
public:
    NullCollector(const std::string& tag):
        LogCollector(tag)
    {}
    virtual ~NullCollector() { }

    virtual int output() { return 0;  }
};

class fdoutbuf: public std::streambuf {
public:
    fdoutbuf(int fd): _fd(fd) { }
    friend class fdostream;
    friend class LogFileCollector;

protected:
    virtual int_type overflow(int_type c) {
        if (c != EOF) {
            char z = c;
            if (write(_fd, &z, 1) != 1) {
                return EOF;
            }
        }
        return c;
    }

    virtual std::streamsize xsputn(const char* s, std::streamsize num) {
        return write(_fd, s, num);
    }

    int _fd;
};

class fdostream: public std::ostream {
public:
    friend class LogFileCollector;

    fdostream(): std::ostream(NULL), _buf(NULL) { }

    void set_buffer(fdoutbuf* buf) {
        if (_buf) {
            delete _buf;
        }
        _buf = buf;
        rdbuf(_buf);
    }

    virtual ~fdostream() { }
protected:
    fdoutbuf*    _buf;
};
 
class LogFileCollector: public LogCollector {
public:
    LogFileCollector(const std::string& file, const std::string& tag = "");
    virtual ~LogFileCollector();
    
    virtual int output() {
        _fos << _os.str() << std::endl;
        _fos.flush();
        _os.str(std::string());
        return 0;
    }

    virtual int fd() { return _fos._buf->_fd; }
    virtual void restart();

    virtual bool good() { return _fos.good(); }

protected:
    void close();
    void open(const std::string& file);

    fdostream _fos;
    std::string _file;
};

template <typename T>
class Log {
public:
    Log();
    virtual ~Log();

    static std::ostringstream& get(LogLevelE level = INFO) { return T::_collector->get(level); }
   
    static LogLevelE getLogLevel() { return T::_level; }
    static void setLogLevel(LogLevelE level) { T::_level = level; }

    static bool setLogLevel(const std::string& level);

    static bool lookupLogLevel(const std::string& level, LogLevelE& value);

    static void setCollector(LogCollector* c) {
        if (T::_collector) {
            delete T::_collector;
        }
        T::_collector = c;
    }

    static LogCollector* getCollector() { return T::_collector; }

    static void restart() {
        LogCollector* c = getCollector();
        if (c) {
            c->restart();
        }
    }

private:
    Log(const Log& log);
    Log& operator = (const Log& rhs);
};

template <typename T>
Log<T>::Log()
{ }

template <typename T>
Log<T>::~Log()
{
    if (T::_collector) {
        T::_collector->output();
    }
}

template <typename T>
bool Log<T>::lookupLogLevel(const std::string& level, LogLevelE& value)
{
    std::map<std::string, LogLevelE>::iterator iter = NameToLevelMap.find(level);
    if (iter == NameToLevelMap.end()) {
        return false;
    }
    value = NameToLevelMap[level];
    return true;
}

template <typename T>
bool Log<T>::setLogLevel(const std::string& level)
{
    LogLevelE levelE;
    if (!lookupLogLevel(level, levelE)) {
        return false;
    }
    Log<T>::setLogLevel(levelE);
    return true;
}

inline LogFileCollector::LogFileCollector(const std::string& file, const std::string& tag) : LogCollector(tag)
{
    this->open(file);
}

inline void LogFileCollector::open(const std::string& file)
{
    int err = ::open(file.c_str(), O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
    if (err == -1) {
        std::cerr << "could not open file '" << file << "'" << std::endl;
        return;
    }
    int fd = err;
    fdoutbuf* b = new fdoutbuf(fd);
    _fos.set_buffer(b);
    if (!_fos.good()) {
        std::cerr << "could not open file '" << file << "'" << std::endl;
        return;
    }
    _file = file;
}

inline void LogFileCollector::close()
{
    std::cerr << "closing file collector" << std::endl;
    if (_fos.good()) {
        this->output();
        ::close(_fos._buf->_fd);
    }
    _fos.set_buffer(NULL);
}

inline LogFileCollector::~LogFileCollector()
{
    this->close();
}

inline void LogFileCollector::restart()
{
    this->close();
    this->open(_file);
}

inline std::string timestamp()
{
    struct timeval tod;
    gettimeofday(&tod, NULL);
    struct tm* t = localtime(&tod.tv_sec);
    char buffer[256];
    // YYYYMMDD-HH:MM:SS.mmm
    snprintf(buffer, sizeof(buffer), "%4d%02d%02d %02d:%02d:%02d%s%03d"
             , t->tm_year + 1900
             , t->tm_mon  + 1
             , t->tm_mday
             , t->tm_hour
             , t->tm_min
             , t->tm_sec
             , "."
             , (int)(tod.tv_usec / 1000)
             );
    return buffer;
}


#define DECLARE_LOG(logname) \
class __##logname { public: static LogLevelE _level; static LogCollector* _collector; }; \
class logname: public Log<__##logname> { public: };

#define DEFINE_LOG(logname) \
LogLevelE __##logname::_level = INFO; \
LogCollector* __##logname::_collector = new LogCollector();

#define DECLARE_FILE_LOG(filename, logname) \
class __##logname { public: static LogLevelE _level; static LogFileCollector* _collector ; }; \
class logname: public Log<__##logname> { public: };

#define DEFINE_FILE_LOG(filename, logname) \
LogLevelE __##logname::_level = INFO; \
LogFileCollector* __##logname::_collector = new LogFileCollector(filename);

#define LOG(log, level) \
    if (level >= NONE) ;\
    else if (level > log::getLogLevel()) ;\
    else log().get(level)

// a few conveniences..
#define LOGTRACE(log) \
    LOG(log, DEBUG) << __FILE__ << ":" << __LINE__ << " [TRACE] " << __PRETTY_FUNCTION__ << "()"

#define LOGTRACEOBJ(log) \
    LOG(log, DEBUG) << __FILE__ << ":" << __LINE__ << " [TRACE this=" << static_cast<void*>(this) << "] " << __PRETTY_FUNCTION__ << "()"

#define LOGFN(log, lvl) \
    LOG(log, lvl) << __FILE__ << ":" << __LINE__ << " " << __FUNCTION__ << "() - "

// in order to use STACKFN, you will need to include "stack_trace.h" first
#if defined(__CYGWIN__)
#define STACKFN(log, level)
#else
#define STACKFN(log, level) \
    LOG(log, level) << __FILE__ << ":" << __LINE__ << " [STACK] " << __PRETTY_FUNCTION__ << "()" << std::endl << stack_trace() << std::endl
#endif

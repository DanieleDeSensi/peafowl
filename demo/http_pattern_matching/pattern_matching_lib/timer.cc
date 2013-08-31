/* -*- C++ -*- */

#define _POSIX_C_SOURCE 1
#include <iomanip>
#include "timer.h"

namespace antivirus {

    void
    timer::start() {
        gettimeofday(&_start_time, 0);
        getrusage(RUSAGE_SELF, &_start_rusage);
    }

    void
    timer::stop() {
        gettimeofday(&_stop_time, 0);
        getrusage(RUSAGE_SELF, &_stop_rusage);
    }

    static void
    elapsed(struct timeval &result,
            struct timeval const &start,
            struct timeval const &stop)
    {
        result.tv_sec = stop.tv_sec - start.tv_sec;
        result.tv_usec = stop.tv_usec - start.tv_usec;
        if (result.tv_usec < 0) {
            --result.tv_sec;
            result.tv_usec += 1000000;
        }
    }

    double
    timeval_to_double(timeval const &tv) {
        return (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0;
    }
    
    void
    timer::real_time(timeval &result) const {
        elapsed(result, _start_time, _stop_time);
    }

    double
    timer::real_time() const {
        timeval tv;
        real_time(tv);
        return timeval_to_double(tv);
    }

    void
    timer::cpu_time(timeval &result) const {
        timeval user;
        user_time(user);
        timeval sys;
        sys_time(sys);
        result.tv_sec = user.tv_sec + sys.tv_sec;
        result.tv_usec = user.tv_usec + sys.tv_usec;
        if (result.tv_usec > 1000000) {
            ++result.tv_sec;
            result.tv_usec -= 1000000;
        }
    }
    
    double
    timer::cpu_time() const {
        timeval tv;
        cpu_time(tv);
        return timeval_to_double(tv);
    }

    void
    timer::user_time(timeval &result) const {
        elapsed(result, _start_rusage.ru_utime, _stop_rusage.ru_utime);
    }
        
    double
    timer::user_time() const {
        timeval tv;
        user_time(tv);
        return timeval_to_double(tv);
    }

    void
    timer::sys_time(timeval &result) const {
        elapsed(result, _start_rusage.ru_stime, _stop_rusage.ru_stime);
    }

    double
    timer::sys_time() const {
        timeval tv;
        sys_time(tv);
        return timeval_to_double(tv);
    }

    void
    print_timeval(ostream &out, char const *label, timeval const &tv) {
        using namespace std;

        out.fill(' ');
        out.width(8);
        out.setf(ios_base::left, ios_base::adjustfield);
        out << label;
        out.fill('0');
        out.width(1);
        out << tv.tv_sec / 60 << 'm';
        out.width(1);
        out << tv.tv_sec % 60 << '.';
        out.width(3);
        out << tv.tv_usec / 1000 << 's' << endl;
    }
    
    void
    timer::print(ostream &out) {
        using namespace std;
        
        timeval tv;
        real_time(tv);
        print_timeval(out, "real", tv);
        cpu_time(tv);
        print_timeval(out, "cpu", tv);
        user_time(tv);
        print_timeval(out, "user", tv);
        sys_time(tv);
        print_timeval(out, "sys", tv);
    }
}

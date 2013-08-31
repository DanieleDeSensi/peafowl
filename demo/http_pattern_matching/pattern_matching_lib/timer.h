/* -*- C++ -*- */

#ifndef TIMER_H
#define TIMER_H

#include <ostream>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

namespace antivirus {

    using std::ostream;
    
    class timer {
    public:
        timer() {}
        ~timer() {}

        void start();
        void stop();

        void real_time(timeval &result) const;
        double real_time() const;
        
        void cpu_time(timeval &result) const;
        double cpu_time() const;
        
        void user_time(timeval &result) const;
        double user_time() const;
        
        void sys_time(timeval &result) const;
        double sys_time() const;

        void print(ostream &out);
    private:
        timeval _start_time;
        rusage _start_rusage;
        timeval _stop_time;
        rusage _stop_rusage;
    };
}

#endif /* TIMER_H */

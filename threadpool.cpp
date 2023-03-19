#include "threadpool.h"

// 构造函数，把线程插入线程队列，插入时调用embrace_back()，用匿名函数lambda初始化Thread对象
ThreadPool::ThreadPool(size_t threads) : stop(false){

    for(size_t i = 0; i< threads; ++i)
        workers.emplace_back(
            [this]
            {
                for(;;)
                {
                    // task是一个函数类型，从任务队列接收任务
                    std::function<void()> task;
                    {
                        //给互斥量加锁，锁对象生命周期结束后自动解锁
                        std::unique_lock<std::mutex> lock(this->queue_mutex);

                        //（1）当匿名函数返回false时才阻塞线程，阻塞时自动释放锁。
                        //（2）当匿名函数返回true且受到通知时解阻塞，然后加锁。
                        this->condition.wait(lock,[this]{ return this->stop || !this->tasks.empty(); });

                         if(this->stop && this->tasks.empty())
                            return;

                        //从任务队列取出一个任务
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }                            // 自动解锁
                    task();                      // 执行这个任务
                }
            }
        );
}

// 析构函数，删除所有线程
ThreadPool::~ThreadPool()
{
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
    }
    condition.notify_all();
    for(std::thread &worker: workers)
        worker.join();
}

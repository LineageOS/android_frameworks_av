/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Unit Test for AdjustableMaxPriorityQueue

#define LOG_NDEBUG 0
#define LOG_TAG "AdjustableMaxPriorityQueueTest"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <gtest/gtest.h>
#include <media/AdjustableMaxPriorityQueue.h>
#include <utils/Log.h>

#include <algorithm>
#include <functional>
#include <iterator>
#include <list>
#include <queue>
#include <unordered_map>

namespace android {

class IntUniquePtrComp {
   public:
    bool operator()(const std::unique_ptr<int>& lhs, const std::unique_ptr<int>& rhs) const {
        return *lhs < *rhs;
    }
};

// Test the heap property and make sure it is the same as std::priority_queue.
TEST(AdjustableMaxPriorityQueueTest, BasicAPIS) {
    AdjustableMaxPriorityQueue<std::pair<float, char*>> heap;
    std::priority_queue<std::pair<float, char*>> pq;
    AdjustableMaxPriorityQueue<std::pair<float, char*>> remove_queue;

    // Push a set of values onto both AdjustableMaxPriorityQueue and priority_queue
    // Also compute the sum of those values
    double sum = 0;
    for (int i = 0; i < 10; ++i) {
        float value = 2.1 * i;
        sum += value;
        heap.push(std::pair<float, char*>(value, nullptr));
        pq.push(std::pair<float, char*>(value, nullptr));
        remove_queue.push(std::pair<float, char*>(value, nullptr));
    }

    // Test the iterator by using it to subtract all values from earlier sum
    AdjustableMaxPriorityQueue<std::pair<float, char*>>::iterator it;
    for (it = heap.begin(); it != heap.end(); ++it) {
        sum -= it->first;
    }
    EXPECT_EQ(0, sum);

    // Test the size();
    EXPECT_EQ(10, heap.size());

    // Testing pop() by popping values from both queues and compare if they are the same.
    // Also check each pop is smaller than the previous pop max value.
    float max = 1000;
    while (!heap.empty()) {
        float value = heap.top().first;
        ALOGD("Value is %f ", value);
        EXPECT_EQ(value, pq.top().first);
        EXPECT_LE(value, max);
        max = value;
        heap.pop();
        pq.pop();
    }

    // Test erase() by removing values and ensuring the heap
    // condition is still met as miscellaneous elements are
    // removed from the heap.
    int iteration_mixer = 0;
    float previous_value = remove_queue.top().first;

    while (!remove_queue.empty()) {
        int iteration_count = iteration_mixer % remove_queue.size();

        AdjustableMaxPriorityQueue<std::pair<float, char*>>::iterator iterator =
                remove_queue.begin();

        // Empty loop as we just want to advance the iterator.
        for (int i = 0; i < iteration_count; ++i, ++iterator) {
        }

        remove_queue.erase(iterator);
        float value = remove_queue.top().first;
        remove_queue.pop();

        EXPECT_GE(previous_value, value);

        ++iteration_mixer;
        previous_value = value;
    }
}

TEST(AdjustableMaxPriorityQueueTest, BasicWithMoveOnly) {
    AdjustableMaxPriorityQueue<std::unique_ptr<int>, IntUniquePtrComp> heap;

    auto smaller = std::make_unique<int>(1);
    EXPECT_TRUE(heap.push(std::move(smaller)));
    EXPECT_EQ(1, *heap.top());
    EXPECT_EQ(1, heap.size());

    auto bigger = std::make_unique<int>(2);
    heap.push(std::move(bigger));
    EXPECT_EQ(2, *heap.top());

    auto biggest = std::make_unique<int>(3);
    EXPECT_TRUE(heap.push(std::move(biggest)));

    EXPECT_EQ(3, heap.size());
    // Biggest should be on top.
    EXPECT_EQ(3, *heap.top());

    biggest = heap.consume_top();
    EXPECT_EQ(3, *biggest);

    bigger = heap.consume_top();
    EXPECT_EQ(2, *bigger);

    smaller = heap.consume_top();
    EXPECT_EQ(1, *smaller);

    EXPECT_TRUE(heap.empty());
}

TEST(AdjustableMaxPriorityQueueTest, TestChangingItem) {
    AdjustableMaxPriorityQueue<std::unique_ptr<int>, IntUniquePtrComp> heap;
    using HeapIterator =
            AdjustableMaxPriorityQueue<std::unique_ptr<int>, IntUniquePtrComp>::iterator;

    int testValues[] = {1, 2, 3};
    // Map to save each value's position in the heap.
    std::unordered_map<int, HeapIterator> itemToIterratorMap;

    // Insert the test values into the heap.
    for (auto value : testValues) {
        auto item = std::make_unique<int>(value);
        EXPECT_TRUE(heap.push(std::move(item)));
    }

    // Save each value and its pos in the heap into the map.
    for (HeapIterator iter = heap.begin(); iter != heap.end(); iter++) {
        itemToIterratorMap[*iter->get()] = iter;
    }

    // Change the item with value 1 -> 4. And expects the 4 to be the top of the HEAP after that.
    // After changing, the heap should contain [2,3,4].
    auto newValue = std::make_unique<int>(4);
    itemToIterratorMap[1]->swap(newValue);
    heap.rebuild();
    EXPECT_EQ(4, *heap.top());

    // Change the item with value 2 -> 5. And expects the 5 to be the top of the HEAP after that.
    auto newValue2 = std::make_unique<int>(5);
    itemToIterratorMap[2]->swap(newValue2);
    heap.rebuild();
    EXPECT_EQ(5, *heap.top());
}

TEST(AdjustableMaxPriorityQueueTest, TestErasingItem) {
    AdjustableMaxPriorityQueue<std::unique_ptr<int>, IntUniquePtrComp> heap;
    using HeapIterator =
            AdjustableMaxPriorityQueue<std::unique_ptr<int>, IntUniquePtrComp>::iterator;

    int testValues[] = {1, 2, 3};
    // Map to save each value's position in the heap.
    std::unordered_map<int, HeapIterator> itemToIterratorMap;

    // Insert the test values into the heap.
    for (auto value : testValues) {
        auto item = std::make_unique<int>(value);
        EXPECT_TRUE(heap.push(std::move(item)));
    }

    // Save each value and its pos in the heap into the map.
    for (HeapIterator iter = heap.begin(); iter != heap.end(); iter++) {
        itemToIterratorMap[*iter->get()] = iter;
    }

    // The top of the heap must be 3.
    EXPECT_EQ(3, *heap.top());

    // Remove 3 and the top of the heap should be 2.
    heap.erase(itemToIterratorMap[3]);
    EXPECT_EQ(2, *heap.top());

    // Reset the iter pos in the heap.
    itemToIterratorMap.clear();
    for (HeapIterator iter = heap.begin(); iter != heap.end(); iter++) {
        itemToIterratorMap[*iter->get()] = iter;
    }

    // Remove 2 and the top of the heap should be 1.
    heap.erase(itemToIterratorMap[2]);
    EXPECT_EQ(1, *heap.top());

    // Reset the iter pos in the heap as iterator pos changed after
    itemToIterratorMap.clear();
    for (HeapIterator iter = heap.begin(); iter != heap.end(); iter++) {
        itemToIterratorMap[*iter->get()] = iter;
    }

    // Remove 1 and the heap should be empty.
    heap.erase(itemToIterratorMap[1]);
    EXPECT_TRUE(heap.empty());
}

// Test the heap property and make sure it is the same as std::priority_queue.
TEST(AdjustableMaxPriorityQueueTest, TranscodingJobTest) {
    // Test data structure that mimics the Transcoding job.
    struct TranscodingJob {
        int32_t priority;
        int64_t createTimeUs;
    };

    // The job is arranging according to priority with highest priority comes first.
    // For the job with the same priority, the job with early createTime will come first.
    class TranscodingJobComp {
       public:
        bool operator()(const std::unique_ptr<TranscodingJob>& lhs,
                        const std::unique_ptr<TranscodingJob>& rhs) const {
            if (lhs->priority != rhs->priority) {
                return lhs->priority < rhs->priority;
            }
            return lhs->createTimeUs > rhs->createTimeUs;
        }
    };

    // Map to save each value's position in the heap.
    std::unordered_map<int, TranscodingJob*> jobIdToJobMap;

    TranscodingJob testJobs[] = {
            {1 /*priority*/, 66 /*createTimeUs*/},  // First job,
            {2 /*priority*/, 67 /*createTimeUs*/},  // Second job,
            {2 /*priority*/, 66 /*createTimeUs*/},  // Third job,
            {3 /*priority*/, 68 /*createTimeUs*/},  // Fourth job.
    };

    AdjustableMaxPriorityQueue<std::unique_ptr<TranscodingJob>, TranscodingJobComp> jobQueue;

    // Pushes all the jobs into the heap.
    for (int jobId = 0; jobId < 4; ++jobId) {
        auto newJob = std::make_unique<TranscodingJob>(testJobs[jobId]);
        jobIdToJobMap[jobId] = newJob.get();
        EXPECT_TRUE(jobQueue.push(std::move(newJob)));
    }

    // Check the job queue size.
    EXPECT_EQ(4, jobQueue.size());

    // Check the top and it should be Forth job: (3, 68)
    const std::unique_ptr<TranscodingJob>& topJob = jobQueue.top();
    EXPECT_EQ(3, topJob->priority);
    EXPECT_EQ(68, topJob->createTimeUs);

    // Consume the top.
    std::unique_ptr<TranscodingJob> consumeJob = jobQueue.consume_top();

    // Check the top and it should be Third Job (2, 66)
    const std::unique_ptr<TranscodingJob>& topJob2 = jobQueue.top();
    EXPECT_EQ(2, topJob2->priority);
    EXPECT_EQ(66, topJob2->createTimeUs);

    // Change the Second job's priority to 4 from (2, 67) -> (4, 67). It should becomes top of the
    // queue.
    jobIdToJobMap[1]->priority = 4;
    jobQueue.rebuild();
    const std::unique_ptr<TranscodingJob>& topJob3 = jobQueue.top();
    EXPECT_EQ(4, topJob3->priority);
    EXPECT_EQ(67, topJob3->createTimeUs);
}
}  // namespace android
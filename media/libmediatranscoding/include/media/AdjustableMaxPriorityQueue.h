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

#ifndef ANDROID_MEDIA_ADJUSTABLE_MAX_PRIORITY_QUEUE_H
#define ANDROID_MEDIA_ADJUSTABLE_MAX_PRIORITY_QUEUE_H

#include <utils/Log.h>

#include <functional>
#include <iostream>
#include <vector>

namespace android {

/*
 * AdjustableMaxPriorityQueue is a custom max priority queue that helps managing jobs for
 * MediaTranscodingService.
 *
 * AdjustableMaxPriorityQueue is a wrapper template around the STL's *_heap() functions.
 * - Internally, it uses a std::vector<T> to store elements in a heap order.
 * - Support adjusting item's priority while maintaining the heap property.
 * - Support removing any item in the heap while maintaining the heap property. Note that the
 *   removal complexity will be O(n) in worst case.
 * - AdjustableMaxPriorityQueue needs T::operator<() at instantiation time
 */
template <class T, class Comparator = std::less<T>>
class AdjustableMaxPriorityQueue {
   public:
    typedef typename std::vector<T>::iterator iterator;
    typedef typename std::vector<T>::const_iterator const_iterator;

    AdjustableMaxPriorityQueue();

    /* Whether the queue is empty. */
    bool empty() const;

    /* Number of items in the queue. */
    int size() const;

    /* Return the top element in the queue. The queue still owns the element. */
    const T& top() const;

    /* Discards the element with highest value based on the given comparator. */
    void pop();

    /* Erases all the elements in the queue. */
    void clear();

    /*
     * Returns the element with the highest value based on the given comparator. Queue transfer the
     * ownership of the item to the caller. Client MUST call empty() to check whether there is
     * element at the top before calling this.
     */
    T consume_top();

    /* Adds an element to the heap. The queue will make a deep copy of the element. */
    bool push(const T& item) { return pushInternal(item); }

    /* Adds an element to the heap. The queue will take ownership of the element. */
    bool push(T&& item) { return pushInternal(std::move(item)); }

    /* Adds a new element to the AdjustableMaxPriorityQueue. This new element is constructed in
     * place passing args as the arguments for its constructor. */
    template <class... Args>
    bool emplace(Args&&... args);

    /* Remove an element from a AdjustableMaxPriorityQueue. */
    void erase(iterator pos);

    /*
     * Rebuild a heap based on the given comparator. This MUST be called after changing the value
     * of items.
     */
    void rebuild();

    /*
     * Iterators used for accessing and changing the priority.
     * If you change the value of items through these access iterators BE SURE to call rebuild() to
     * ensure the integrity of the heap is maintained.
     * NOTE: The iterator pos will change after calling rebuild().
     */
    const iterator begin();
    const iterator end();

    /*
     * Iterators used for accessing the priority.
     */
    const const_iterator begin() const;
    const const_iterator end() const;

    /* Return the backbone storage of this PriorityQueue. Mainly used for debugging. */
    const std::vector<T>& getStorage() const { return mHeap; };

   private:
    std::vector<T> mHeap;

    /* Implementation shared by both public push() methods. */
    template <class Arg>
    bool pushInternal(Arg&& item);
};

template <class T, class Comparator>
AdjustableMaxPriorityQueue<T, Comparator>::AdjustableMaxPriorityQueue() {}

template <class T, class Comparator>
bool AdjustableMaxPriorityQueue<T, Comparator>::empty() const {
    return mHeap.empty();
}

template <class T, class Comparator>
int AdjustableMaxPriorityQueue<T, Comparator>::size() const {
    return mHeap.size();
}

template <class T, class Comparator>
const T& AdjustableMaxPriorityQueue<T, Comparator>::top() const {
    DCHECK(!mHeap.empty());
    return mHeap.front();
}

// Compares elements and potentially swaps (or moves) them until rearranged as a longer heap.
// Complexity of this: Up to logarithmic in the distance between first and last.
template <class T, class Comparator>
template <class Arg>
bool AdjustableMaxPriorityQueue<T, Comparator>::pushInternal(Arg&& item) {
    mHeap.push_back(std::forward<Arg>(item));
    std::push_heap(mHeap.begin(), mHeap.end(), Comparator());
    return true;
}

template <class T, class Comparator>
template <class... Args>
bool AdjustableMaxPriorityQueue<T, Comparator>::emplace(Args&&... args) {
    mHeap.emplace_back(std::forward<Args>(args)...);
    std::push_heap(mHeap.begin(), mHeap.end(), Comparator());
    return true;
}

// Compares elements and potentially swaps (or moves) them until rearranged as a shorter heap.
// Complexity of this: Up to twice logarithmic in the distance between first and last.
template <class T, class Comparator>
void AdjustableMaxPriorityQueue<T, Comparator>::pop() {
    DCHECK(!mHeap.empty());
    std::pop_heap(mHeap.begin(), mHeap.end(), Comparator());
    mHeap.pop_back();
}

// Compares elements and potentially swaps (or moves) them until rearranged as a shorter heap.
// Complexity of this: Up to twice logarithmic in the distance between first and last.
template <class T, class Comparator>
T AdjustableMaxPriorityQueue<T, Comparator>::consume_top() {
    DCHECK(!mHeap.empty());
    std::pop_heap(mHeap.begin(), mHeap.end(), Comparator());
    T to_return = std::move(mHeap.back());
    mHeap.pop_back();
    return to_return;
}

template <class T, class Comparator>
const typename AdjustableMaxPriorityQueue<T, Comparator>::iterator
AdjustableMaxPriorityQueue<T, Comparator>::begin() {
    return mHeap.begin();
}

template <class T, class Comparator>
const typename AdjustableMaxPriorityQueue<T, Comparator>::iterator
AdjustableMaxPriorityQueue<T, Comparator>::end() {
    return mHeap.end();
}

template <class T, class Comparator>
const typename AdjustableMaxPriorityQueue<T, Comparator>::const_iterator
AdjustableMaxPriorityQueue<T, Comparator>::begin() const {
    return mHeap.begin();
}

template <class T, class Comparator>
const typename AdjustableMaxPriorityQueue<T, Comparator>::const_iterator
AdjustableMaxPriorityQueue<T, Comparator>::end() const {
    return mHeap.end();
}

template <class T, class Comparator>
void AdjustableMaxPriorityQueue<T, Comparator>::clear() {
    mHeap.erase(mHeap.begin(), mHeap.end());
}

// Complexity of this: At most 3*std::distance(first, last) comparisons.
template <class T, class Comparator>
void AdjustableMaxPriorityQueue<T, Comparator>::rebuild() {
    std::make_heap(mHeap.begin(), mHeap.end(), Comparator());
}

// Remove a random element from a AdjustableMaxPriorityQueue.
template <class T, class Comparator>
void AdjustableMaxPriorityQueue<T, Comparator>::erase(iterator pos) {
    DCHECK(!mHeap.empty());
    mHeap.erase(pos);
    rebuild();
}

}  // namespace android
#endif  // ANDROID_MEDIA_ADJUSTABLE_MAX_PRIORITY_QUEUE_H
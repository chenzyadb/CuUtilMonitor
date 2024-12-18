// CuPairList by chenzyadb@github.com
// Based on C++17 STL (GNUC)

#if !defined(__CU_PAIR_LIST__)
#define __CU_PAIR_LIST__ 1

#include <exception>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <utility>

namespace CU
{
	class PairListExcept : public std::exception
	{
		public:
			PairListExcept(const std::string &message) : message_(message) { }

			const char* what() const noexcept override
			{
				return message_.c_str();
			}

		private:
			const std::string message_;
	};

	template <typename _Key_Ty, typename _Val_Ty>
	class PairList
	{
		public:
			class Pair 
			{
				public:
					Pair() : key_(), value_() { }

					Pair(const _Key_Ty &key, const _Val_Ty &value) : key_(key), value_(value) { }

					Pair(const Pair &other) : key_(other.key()), value_(other.value()) { }

					Pair(Pair &&other) noexcept : key_(other.key_rv()), value_(other.value_rv()) { }

					Pair &operator=(const Pair &other)
					{
						if (std::addressof(other) != this) {
							key_ = other.key();
							value_ = other.value();
						}
						return *this;
					}

					Pair &operator=(Pair &&other) noexcept
					{
						if (std::addressof(other) != this) {
							key_ = other.key();
							value_ = other.value();
						}
						return *this;
					}

					bool operator==(const Pair &other) const
					{
						if (std::addressof(other) == this) {
							return true;
						}
						return (key_ == other.key() && value_ == other.value());
					}

					bool operator!=(const Pair &other) const
					{
						if (std::addressof(other) == this) {
							return false;
						}
						return (key_ != other.key() || value_ != other.value());
					}

					bool operator<(const Pair &other) const
					{
						if (std::addressof(other) == this) {
							return false;
						}
						return (key_ < other.key());
					}

					bool operator>(const Pair &other) const
					{
						if (std::addressof(other) == this) {
							return false;
						}
						return (key_ > other.key());
					}

					_Key_Ty &key()
					{
						return key_;
					}

					const _Key_Ty &key() const
					{
						return key_;
					}

					_Val_Ty &value()
					{
						return value_;
					}

					const _Val_Ty &value() const
					{
						return value_;
					}

					_Key_Ty &&key_rv()
					{
						return std::move(key_);
					}

					_Val_Ty &&value_rv()
					{
						return std::move(value_);
					}

				private:
					_Key_Ty key_;
					_Val_Ty value_;
			};

			typedef typename std::vector<Pair>::iterator iterator;
			typedef typename std::vector<Pair>::const_iterator const_iterator;

			PairList() : data_() { }

			PairList(const PairList &other) : 
				data_(other.data())
			{ }

			PairList(PairList &&other) noexcept : 
				data_(other.data_rv())
			{ }

			~PairList() { }

			PairList &operator=(const PairList &other)
			{
				if (std::addressof(other) != this) {
					data_ = other.data();
				}
				return *this;
			}

			PairList &operator=(PairList &&other) noexcept
			{
				if (std::addressof(other) != this) {
					data_ = other.data_rv();
				}
				return *this;
			}

			bool operator==(const PairList &other) const
			{
				if (std::addressof(other) == this) {
					return true;
				}
				return (other.data() == data_);
			}

			bool operator!=(const PairList &other) const
			{
				if (std::addressof(other) == this) {
					return false;
				}
				return (other.data() != data_);
			}

			_Val_Ty &operator[](const _Key_Ty &key)
			{
				for (auto &item : data_) {
					if (item.key() == key) {
						return item.value();
					}
				}
				data_.emplace_back(key, _Val_Ty());
				return data_.back().value();
			}

			_Key_Ty &operator()(const _Val_Ty &value)
			{
				for (auto &item : data_) {
					if (item.value() == value) {
						return item.key();
					}
				}
				data_.emplace_back(_Key_Ty(), value);
				return data_.back().key();
			}

			const _Val_Ty &atKey(const _Key_Ty &key) const
			{
				for (const auto &item : data_) {
					if (item.key() == key) {
						return item.value();
					}
				}
				throw PairListExcept("Key not found");
			}

			const _Key_Ty &atValue(const _Val_Ty &value) const
			{
				for (const auto &item : data_) {
					if (item.value() == value) {
						return item.key();
					}
				}
				throw PairListExcept("Value not found");
			}

			bool containsKey(const _Key_Ty &key) const
			{
				for (const auto &item : data_) {
					if (item.key() == key) {
						return true;
					}
				}
				return false;
			}

			bool containsValue(const _Val_Ty &value) const
			{
				for (const auto &item : data_) {
					if (item.value() == value) {
						return true;
					}
				}
				return false;
			}

			const_iterator begin() const
			{
				return data_.begin();
			}

			const_iterator end() const
			{
				return data_.end();
			}

			Pair front() const
			{
				return data_.front();
			}

			Pair back() const
			{
				return data_.back();
			}

			const_iterator findKey(const _Key_Ty &key) const
			{
				for (auto iter = data_.begin(); iter < data_.end(); ++iter) {
					if (iter->key() == key) {
						return iter;
					}
				}
				return data_.end();
			}

			const_iterator findValue(const _Val_Ty &value) const
			{
				for (auto iter = data_.begin(); iter < data_.end(); ++iter) {
					if (iter->value() == value) {
						return iter;
					}
				}
				return data_.end();
			}

			void add(const _Key_Ty &key, const _Val_Ty &value)
			{
				data_.emplace_back(key, value);
			}

			void add(const Pair &pair)
			{
				data_.emplace_back(pair);
			}

			void remove(const_iterator iter)
			{
				data_.erase(iter);
			}

			void removeKey(const _Key_Ty &key)
			{
				for (auto iter = data_.begin(); iter < data_.end(); ++iter) {
					if (iter->key() == key) {
						data_.erase(iter);
						break;
					}
				}
			}

			void removeValue(const _Val_Ty &value)
			{
				for (auto iter = data_.begin(); iter < data_.end(); ++iter) {
					if (iter->value() == value) {
						data_.erase(iter);
						break;
					}
				}
			}

			std::vector<_Key_Ty> keys() const
			{
				std::vector<_Key_Ty> pairKeys{};
				for (const auto &pair : data_) {
					pairKeys.emplace_back(pair.key());
				}
				return pairKeys;
			}

			std::vector<_Val_Ty> values() const
			{
				std::vector<_Val_Ty> pairValues{};
				for (const auto &pair : data_) {
					pairValues.emplace_back(pair.value());
				}
				return pairValues;
			}

			const std::vector<Pair> &data() const
			{
				return data_;
			}

			std::vector<Pair> &&data_rv() 
			{
				return std::move(data_);
			}

			void sort()
			{
				std::sort(data_.begin(), data_.end());
			}

			void reverse()
			{
				std::reverse(data_.begin(), data_.end());
			}

			void clear()
			{
				data_.clear();
			}

			size_t size() const noexcept
			{
				return data_.size();
			}

		private:
			std::vector<Pair> data_;
	};
}

#endif // !defined(__CU_PAIR_LIST__)

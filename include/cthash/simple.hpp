#ifndef CTHASH_SIMPLE_HPP
#define CTHASH_SIMPLE_HPP

#include <utility>

namespace cthash {

template <typename Hasher, typename In, typename... Args> concept hasher_like = requires(Hasher & h, const In & in, Args &&... args) //
{
	{ Hasher{std::forward<Args>(args)...} };
	{ h.update(in) } -> std::same_as<Hasher &>;
	{ h.final() };
};

template <typename Hasher, typename T, typename... Args>
requires hasher_like<Hasher, T, Args...>
constexpr auto simple(const T & value, Args &&... args) noexcept {
	return Hasher{std::forward<Args>(args)...}.update(value).final();
}

} // namespace cthash

#endif

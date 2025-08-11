// giltools.cpp (fixed: no py::object used after GIL release)
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <cstdint>

#ifdef _WIN32
  #define NOMINMAX
  #include <windows.h>
#endif

namespace py = pybind11;

// --------------------------- helpers ---------------------------
static void yield_no_gil(double seconds = 0.0) {
  // Convert args under GIL (already in Python frame), then release
  py::gil_scoped_release release;
  if (seconds > 0.0) {
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
  } else {
    std::this_thread::yield();
  }
}

#ifdef _WIN32
static int wait_handle_no_gil(uintptr_t handle_value, int timeout_ms = -1) {
  // No Python objects used inside this scope
  py::gil_scoped_release release;
  HANDLE h = reinterpret_cast<HANDLE>(handle_value);
  DWORD to = (timeout_ms < 0) ? INFINITE : static_cast<DWORD>(timeout_ms);
  DWORD r = WaitForSingleObject(h, to);
  if (r == WAIT_OBJECT_0)  return 0;
  if (r == WAIT_TIMEOUT)   return 1;
  if (r == WAIT_ABANDONED) return 2;
  return 3;
}
#endif

static void burn_no_gil(double seconds, int threads = -1) {
  // Parse/normalize args while GIL is held (we're still in Python call frame)
  int hw = (int)std::thread::hardware_concurrency();
  if (threads < 1) threads = (hw > 0 ? hw : 1);

  // Now drop the GIL and do native work
  py::gil_scoped_release release;

  std::atomic<bool> stop{false};
  auto worker = [&stop](int) {
    double x = 0.0;
    while (!stop.load(std::memory_order_relaxed)) {
      x = x * 1.0000001 + 1.0;
      if (x > 1e6) x = 0.0;
    }
  };
  std::vector<std::thread> pool; pool.reserve(threads);
  for (int i = 0; i < threads; ++i) pool.emplace_back(worker, i);
  std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
  stop.store(true, std::memory_order_relaxed);
  for (auto &t : pool) if (t.joinable()) t.join();
}

// --------------------------- process “unhinge” (Windows only) ---------------------------
#ifdef _WIN32
static void _disable_eco_throttling() {
  struct PROCESS_POWER_THROTTLING_STATE { ULONG Version, ControlMask, StateMask; };
  PROCESS_POWER_THROTTLING_STATE st{1, 1/*EXECUTION_SPEED*/, 0/*disable*/};
  SetProcessInformation(GetCurrentProcess(), (PROCESS_INFORMATION_CLASS)9, &st, sizeof(st));
}
static void _set_high_priority() { SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS); }
static void _set_process_affinity(const std::vector<int>& cores) {
  if (cores.empty()) return;
  unsigned long long m = 0;
  for (int c : cores) if (c >= 0 && c < 64) m |= (1ull << c);
  if (m) SetProcessAffinityMask(GetCurrentProcess(), (DWORD_PTR)m);
}
static void _pin_this_thread_to_core(int core) {
  if (core >= 0 && core < 64) SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)(1ull << core));
}
#else
static void _disable_eco_throttling() {}
static void _set_high_priority() {}
static void _set_process_affinity(const std::vector<int>&) {}
static void _pin_this_thread_to_core(int) {}
#endif

static void unhinge_process(const std::vector<int>& cores = {},
                            bool high_priority = true,
                            bool disable_eco = true) {
  // No Python objects beyond this point
  py::gil_scoped_release release;
  if (disable_eco) _disable_eco_throttling();
  if (high_priority) _set_high_priority();
  if (!cores.empty()) _set_process_affinity(cores);
}

// --------------------------- persistent CPU boost ---------------------------
static std::atomic<bool> g_boost_running{false};
static std::vector<std::thread> g_boost_threads;
static std::vector<int> g_core_list;

static void _boost_worker(double util, int idx, bool pin) {
  if (util < 0.0) util = 0.0;
  if (util > 1.0) util = 1.0;

  if (pin && !g_core_list.empty()) {
    int core = g_core_list[idx % (int)g_core_list.size()];
    _pin_this_thread_to_core(core);
  }

  using clk = std::chrono::steady_clock;
  const auto slice = std::chrono::microseconds(1000);

  auto burn_for = [](std::chrono::nanoseconds ns){
    auto start = clk::now();
    double x = 0.0;
    while (clk::now() - start < ns) {
      x = x * 1.0000001 + 1.0;
      if (x > 1e6) x = 0.0;
    }
  };

  while (g_boost_running.load(std::memory_order_acquire)) {
    if (util <= 0.0) {
      std::this_thread::sleep_for(slice);
      continue;
    }
    if (util >= 1.0) {
      burn_for(slice);
      continue;
    }
    const auto busy_ns = std::chrono::nanoseconds((long long)(util * 1e6));       // util * 1ms
    const auto idle_ns = std::chrono::nanoseconds((long long)((1.0 - util) * 1e6));
    burn_for(busy_ns);
    std::this_thread::sleep_for(idle_ns);
  }
}

static void start_cpu_boost(int threads = -1,
                            double target_util = 1.0,
                            const std::vector<int>& cores = {},
                            bool pin_per_thread = true,
                            bool unhinge = true) {
  // Normalize args under GIL
  if (g_boost_running.load(std::memory_order_acquire)) return;
  int hw = (int)std::thread::hardware_concurrency();
  if (threads < 1) threads = (hw > 0 ? hw : 1);
  g_core_list = cores; // safe here; not running yet

  // Now drop the GIL and do native work
  py::gil_scoped_release release;

  if (unhinge) {
    if (!cores.empty()) _set_process_affinity(cores);
    _disable_eco_throttling();
    _set_high_priority();
  }

  g_boost_running.store(true, std::memory_order_release);
  g_boost_threads.clear();
  g_boost_threads.reserve(threads);
  for (int i = 0; i < threads; ++i)
    g_boost_threads.emplace_back(_boost_worker, target_util, i, pin_per_thread);
}

static void stop_cpu_boost() {
  py::gil_scoped_release release;
  if (!g_boost_running.exchange(false, std::memory_order_acq_rel)) return;
  for (auto &t : g_boost_threads) if (t.joinable()) t.join();
  g_boost_threads.clear();
  g_core_list.clear();
}

static bool is_cpu_boost_running() {
  return g_boost_running.load(std::memory_order_acquire);
}

// --------------------------- module ---------------------------
PYBIND11_MODULE(giltools, m) {
  m.doc() = "Helpers to drop the GIL and to drive CPU usage via native threads.";

  // existing
  m.def("yield_no_gil", &yield_no_gil, py::arg("seconds") = 0.0,
        "Release the GIL for `seconds` (0 -> just yield).");
#ifdef _WIN32
  m.def("wait_handle_no_gil", &wait_handle_no_gil,
        py::arg("handle"), py::arg("timeout_ms") = -1,
        "Wait on a Win32 HANDLE without the GIL. Returns 0 OK, 1 timeout, 2 abandoned, 3 fail.");
#endif
  m.def("burn_no_gil", &burn_no_gil, py::arg("seconds"), py::arg("threads") = -1,
        "One-shot burn: spin threads for `seconds` with the GIL released.");

  // new
  m.def("unhinge_process", &unhinge_process,
        py::arg("cores") = std::vector<int>{},
        py::arg("high_priority") = true,
        py::arg("disable_eco") = true,
        "Windows: disable Eco throttling, raise priority, optional process affinity.");

  m.def("start_cpu_boost", &start_cpu_boost,
        py::arg("threads") = -1,
        py::arg("target_util") = 1.0,
        py::arg("cores") = std::vector<int>{},
        py::arg("pin_per_thread") = true,
        py::arg("unhinge") = true,
        "Start persistent CPU load (0..1 target_util). Optional core list + pinning.");

  m.def("stop_cpu_boost", &stop_cpu_boost,
        "Stop the persistent CPU load.");

  m.def("is_cpu_boost_running", &is_cpu_boost_running,
        "Return True if boost workers are running.");
}

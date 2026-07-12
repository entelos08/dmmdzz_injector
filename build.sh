#!/usr/bin/env bash
# =============================================================================
# build.sh  -  Linux 宿主机一键交叉编译脚本
#
# 目标平台 : Windows x86_64
# 工具链   : MinGW-w64 (gcc/g++/windres)
# 构建系统 : CMake
#
# 用法:
#   ./build.sh                  # 默认 Release, 启用 usermode + asm
#   ./build.sh Debug            # 指定构建类型
#   ./build.sh Release skipasm  # 跳过 asm 模块 (没装 nasm 时用)
#
# 依赖安装 (Debian/Ubuntu):
#   sudo apt install mingw-w64 cmake nasm
# 依赖安装 (Arch):
#   sudo pacman -S mingw-w64-gcc cmake nasm
# 依赖安装 (Fedora):
#   sudo dnf install mingw64-gcc mingw64-gcc-c++ cmake nasm
# =============================================================================
set -euo pipefail

# ----------------------------- 配置 ----------------------------------------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLCHAIN_FILE="${PROJECT_ROOT}/cmake/toolchain-mingw-x86_64.cmake"
BUILD_DIR="${PROJECT_ROOT}/build"
BUILD_TYPE="${1:-Release}"
SKIP_ASM="${2:-}"

# ----------------------------- 颜色输出 ------------------------------------
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
BLUE=$'\033[34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
log()  { echo "${BLUE}[*]${RESET} $*"; }
ok()   { echo "${GREEN}[+]${RESET} $*"; }
warn() { echo "${YELLOW}[!]${RESET} $*"; }
err()  { echo "${RED}[!]${RESET} $*" >&2; }

# ----------------------------- 依赖检查 ------------------------------------
log "检查交叉编译工具链..."
need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "未找到 '$1'。请先安装: $2"
        exit 1
    fi
}

need_cmd x86_64-w64-mingw32-gcc   "sudo apt install mingw-w64"
need_cmd x86_64-w64-mingw32-g++   "sudo apt install mingw-w64"
need_cmd x86_64-w64-mingw32-windres "sudo apt install mingw-w64"
need_cmd cmake                     "sudo apt install cmake"

# NASM 是可选的 (asm 模块)
HAVE_NASM=0
if command -v nasm >/dev/null 2>&1; then
    HAVE_NASM=1
    ok "找到 nasm: $(nasm -v)"
else
    warn "未找到 nasm, 将跳过 asm 教学模块 (可运行: sudo apt install nasm)"
    SKIP_ASM=1
fi

# ----------------------------- 打印环境 ------------------------------------
echo
echo "${BOLD}============================================================${RESET}"
echo "${BOLD} dmmdzz_injector - Linux -> Windows 交叉编译${RESET}"
echo "${BOLD}============================================================${RESET}"
echo " 项目根目录   : ${PROJECT_ROOT}"
echo " 构建目录     : ${BUILD_DIR}"
echo " 构建类型     : ${BUILD_TYPE}"
echo " Toolchain    : ${TOOLCHAIN_FILE}"
echo " GCC          : $(x86_64-w64-mingw32-gcc --version | head -n1)"
echo " G++          : $(x86_64-w64-mingw32-g++ --version | head -n1)"
echo " CMake        : $(cmake --version | head -n1)"
echo " NASM         : $([ ${HAVE_NASM} -eq 1 ] && nasm -v || echo '未安装')"
echo "${BOLD}============================================================${RESET}"
echo

# ----------------------------- CMake 配置 ----------------------------------
log "清理旧的构建目录..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

EXTRA_FLAGS=()
if [ "${SKIP_ASM}" = "1" ] || [ "${SKIP_ASM}" = "skipasm" ]; then
    log "跳过 asm 模块 (-DBUILD_ASM=OFF)"
    EXTRA_FLAGS+=("-DBUILD_ASM=OFF")
fi

# 驱动 (.sys) 在 Linux 上无法编译, 始终关闭
EXTRA_FLAGS+=("-DBUILD_DRIVER=OFF")

log "运行 CMake 配置..."
cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    "${EXTRA_FLAGS[@]}"

# ----------------------------- 编译 ----------------------------------------
log "开始编译 (cmake --build)..."
cmake --build "${BUILD_DIR}" -j"$(nproc)"

# ----------------------------- 结果汇总 ------------------------------------
echo
echo "${BOLD}============================================================${RESET}"
echo "${GREEN}${BOLD} 编译完成!${RESET}"
echo "${BOLD}============================================================${RESET}"
echo
echo " 产物位置: ${BUILD_DIR}/bin/"
ls -lh "${BUILD_DIR}/bin/" 2>/dev/null || true
echo
echo " 部署到 Windows:"
echo "   1. 将 ${BUILD_DIR}/bin/dmmdzz_ctl.exe 拷到 Windows 测试机"
if [ ${HAVE_NASM} -eq 1 ]; then
echo "   2. (可选) 拷 ${BUILD_DIR}/bin/dmmdzz_asm_demo.exe 用于学习 NASM 链接"
fi
echo
echo " 驱动 .sys 需在 Windows 主机上用 WDK 单独构建, 详见 README.md 第 4 节"
echo

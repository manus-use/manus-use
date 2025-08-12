#!/bin/bash
# Safe Research Environment Setup for CVE-2025-5958 Analysis
# EDUCATIONAL PURPOSE ONLY - NO EXPLOITATION

echo "=== CVE-2025-5958 Safe Research Environment Setup ==="
echo "⚠️  FOR EDUCATIONAL AND DEFENSIVE RESEARCH ONLY"
echo ""

# Check if running in VM
check_vm_environment() {
    echo "🔍 Checking if running in safe VM environment..."
    
    # Check for common VM indicators
    if [ -f /proc/cpuinfo ]; then
        if grep -q "hypervisor" /proc/cpuinfo; then
            echo "✅ VM environment detected"
            return 0
        fi
    fi
    
    # Check for VM-specific files/directories
    if [ -d "/proc/vz" ] || [ -f "/proc/xen" ]; then
        echo "✅ Virtualized environment detected"
        return 0
    fi
    
    echo "⚠️  WARNING: Not running in detected VM environment"
    echo "   Please ensure you're in an isolated environment"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
}

# Network isolation check
check_network_isolation() {
    echo ""
    echo "🌐 Checking network connectivity..."
    
    if ping -c 1 8.8.8.8 &> /dev/null; then
        echo "⚠️  WARNING: Network connectivity detected"
        echo "   For safe research, consider disconnecting from internet"
        read -p "Continue with network enabled? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Please disconnect network and run again"
            exit 1
        fi
    else
        echo "✅ Network appears isolated"
    fi
}

# Create research directory structure
setup_research_directory() {
    echo ""
    echo "📁 Setting up research directory structure..."
    
    RESEARCH_DIR="$HOME/cve-2025-5958-research"
    mkdir -p "$RESEARCH_DIR"/{logs,samples,analysis,tools,reports}
    
    echo "✅ Created research directory: $RESEARCH_DIR"
    echo "   - logs/     : For debugging and crash logs"
    echo "   - samples/  : For test HTML/media files"
    echo "   - analysis/ : For analysis results"
    echo "   - tools/    : For research tools"
    echo "   - reports/  : For documentation"
    
    cd "$RESEARCH_DIR"
}

# Install analysis tools
install_analysis_tools() {
    echo ""
    echo "🔧 Installing analysis tools..."
    
    # Check if running on supported system
    if command -v apt-get &> /dev/null; then
        echo "Installing tools via apt-get..."
        sudo apt-get update
        sudo apt-get install -y \
            gdb \
            valgrind \
            strace \
            ltrace \
            hexdump \
            binutils \
            curl \
            wget
    elif command -v yum &> /dev/null; then
        echo "Installing tools via yum..."
        sudo yum install -y \
            gdb \
            valgrind \
            strace \
            ltrace \
            binutils \
            curl \
            wget
    else
        echo "⚠️  Package manager not detected. Please install manually:"
        echo "   - gdb (debugger)"
        echo "   - valgrind (memory analysis)"
        echo "   - strace (system call tracer)"
        echo "   - binutils (binary utilities)"
    fi
}

# Create sample test files (safe, non-exploitative)
create_test_samples() {
    echo ""
    echo "📄 Creating safe test samples..."
    
    # Create basic HTML test file
    cat > samples/basic_media_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>CVE-2025-5958 Analysis - Basic Media Test</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>Media Element Analysis</h1>
    <p>This page contains basic media elements for analysis purposes.</p>
    
    <!-- Basic video element -->
    <video id="testVideo" width="320" height="240" controls>
        <source src="test_video.mp4" type="video/mp4">
        <p>Your browser does not support the video tag.</p>
    </video>
    
    <!-- Basic audio element -->
    <audio id="testAudio" controls>
        <source src="test_audio.mp3" type="audio/mpeg">
        <p>Your browser does not support the audio tag.</p>
    </audio>
    
    <script>
        // Basic JavaScript for media interaction analysis
        console.log("Media test page loaded");
        
        const video = document.getElementById('testVideo');
        const audio = document.getElementById('testAudio');
        
        // Log media events for analysis
        ['loadstart', 'loadeddata', 'canplay', 'play', 'pause', 'ended', 'error'].forEach(event => {
            video.addEventListener(event, (e) => {
                console.log(`Video event: ${event}`, e);
            });
            audio.addEventListener(event, (e) => {
                console.log(`Audio event: ${event}`, e);
            });
        });
    </script>
</body>
</html>
EOF

    # Create analysis script
    cat > analysis/analyze_chrome.sh << 'EOF'
#!/bin/bash
# Chrome Analysis Script for CVE-2025-5958 Research

echo "=== Chrome Media Component Analysis ==="
echo "Target: CVE-2025-5958 (Use-after-free in Media)"
echo ""

# Check Chrome version
if command -v google-chrome &> /dev/null; then
    CHROME_VERSION=$(google-chrome --version)
    echo "Chrome Version: $CHROME_VERSION"
    
    # Check if vulnerable version
    if [[ $CHROME_VERSION == *"137.0.7151.10"[0-2]* ]]; then
        echo "⚠️  VULNERABLE VERSION DETECTED"
        echo "   This version is affected by CVE-2025-5958"
    else
        echo "✅ Version appears patched"
    fi
else
    echo "❌ Chrome not found"
    exit 1
fi

echo ""
echo "Starting Chrome with debugging flags..."
echo "⚠️  This will open Chrome with reduced security for analysis"

# Create temporary profile
TEMP_PROFILE="/tmp/chrome-analysis-profile"
rm -rf "$TEMP_PROFILE"
mkdir -p "$TEMP_PROFILE"

# Launch Chrome with analysis flags
google-chrome \
    --user-data-dir="$TEMP_PROFILE" \
    --enable-logging \
    --log-level=0 \
    --enable-heap-profiling \
    --js-flags="--expose-gc --trace-gc" \
    --disable-web-security \
    --disable-features=VizDisplayCompositor \
    --enable-crash-reporter \
    --crash-dumps-dir="$(pwd)/../logs" \
    "file://$(pwd)/../samples/basic_media_test.html" \
    2>&1 | tee "../logs/chrome_debug_$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "Analysis complete. Check logs directory for output."
EOF

    chmod +x analysis/analyze_chrome.sh
    
    echo "✅ Created test samples:"
    echo "   - samples/basic_media_test.html"
    echo "   - analysis/analyze_chrome.sh"
}

# Create monitoring scripts
create_monitoring_tools() {
    echo ""
    echo "📊 Creating monitoring tools..."
    
    # Memory monitoring script
    cat > tools/monitor_memory.sh << 'EOF'
#!/bin/bash
# Memory monitoring for Chrome processes

echo "=== Chrome Memory Monitor ==="
echo "Monitoring Chrome processes for memory anomalies..."
echo "Press Ctrl+C to stop"
echo ""

while true; do
    # Find Chrome processes
    CHROME_PIDS=$(pgrep -f "chrome")
    
    if [ -n "$CHROME_PIDS" ]; then
        echo "$(date): Chrome Memory Usage"
        for pid in $CHROME_PIDS; do
            if [ -f "/proc/$pid/status" ]; then
                PROCESS_NAME=$(grep "Name:" /proc/$pid/status | awk '{print $2}')
                MEMORY_KB=$(grep "VmRSS:" /proc/$pid/status | awk '{print $2}')
                MEMORY_MB=$((MEMORY_KB / 1024))
                echo "  PID $pid ($PROCESS_NAME): ${MEMORY_MB}MB"
            fi
        done
        echo ""
    else
        echo "$(date): No Chrome processes found"
    fi
    
    sleep 5
done
EOF

    chmod +x tools/monitor_memory.sh
    
    # Crash detector script
    cat > tools/detect_crashes.sh << 'EOF'
#!/bin/bash
# Crash detection and analysis

CRASH_DIR="../logs"
echo "=== Chrome Crash Detector ==="
echo "Monitoring for crashes in: $CRASH_DIR"
echo ""

# Monitor crash dumps
inotifywait -m -e create "$CRASH_DIR" 2>/dev/null | while read path action file; do
    if [[ "$file" == *.dmp ]] || [[ "$file" == *crash* ]]; then
        echo "$(date): Crash detected: $file"
        echo "  Location: $path$file"
        
        # Basic crash analysis
        if command -v file &> /dev/null; then
            echo "  File type: $(file "$path$file")"
        fi
        
        echo "  Size: $(ls -lh "$path$file" | awk '{print $5}')"
        echo ""
    fi
done
EOF

    chmod +x tools/detect_crashes.sh
    
    echo "✅ Created monitoring tools:"
    echo "   - tools/monitor_memory.sh"
    echo "   - tools/detect_crashes.sh"
}

# Create documentation
create_documentation() {
    echo ""
    echo "📚 Creating research documentation..."
    
    cat > reports/research_methodology.md << 'EOF'
# CVE-2025-5958 Research Methodology

## Objective
Educational analysis of CVE-2025-5958 (Use-after-free in Chrome Media component) for defensive security research.

## Safety Guidelines
1. **Always use isolated environment**
2. **Never test on production systems**
3. **Document all findings responsibly**
4. **Focus on understanding, not exploitation**

## Research Steps

### 1. Environment Preparation
- [x] Isolated VM setup
- [x] Network isolation verification
- [x] Tool installation
- [x] Sample creation

### 2. Static Analysis
- [ ] Review Chrome source code (if available)
- [ ] Analyze media component architecture
- [ ] Identify potential UAF patterns
- [ ] Document findings

### 3. Dynamic Analysis
- [ ] Run test samples in vulnerable Chrome
- [ ] Monitor memory usage patterns
- [ ] Capture debug logs
- [ ] Analyze crash dumps (if any)

### 4. Defensive Analysis
- [ ] Study the official patch
- [ ] Understand mitigation techniques
- [ ] Develop detection methods
- [ ] Create prevention guidelines

## Tools Used
- Chrome with debugging flags
- GDB for debugging
- Valgrind for memory analysis
- Custom monitoring scripts

## Findings Log
Date: ___________
Researcher: ___________

### Observations:
- 

### Technical Details:
- 

### Defensive Insights:
- 

### Recommendations:
- 

## Ethical Considerations
This research is conducted for:
- Educational purposes
- Defensive security improvement
- Understanding vulnerability mechanics
- Developing better protections

NOT for:
- Exploitation development
- Malicious purposes
- Unauthorized testing
- Harm to systems or users
EOF

    echo "✅ Created research documentation"
}

# Main execution
main() {
    echo "Starting safe research environment setup..."
    
    check_vm_environment
    check_network_isolation
    setup_research_directory
    install_analysis_tools
    create_test_samples
    create_monitoring_tools
    create_documentation
    
    echo ""
    echo "🎉 Safe research environment setup complete!"
    echo ""
    echo "📍 Research directory: $(pwd)"
    echo ""
    echo "🚀 Next steps:"
    echo "   1. Review the methodology in reports/research_methodology.md"
    echo "   2. Run analysis/analyze_chrome.sh to start analysis"
    echo "   3. Use tools/monitor_memory.sh to monitor Chrome"
    echo "   4. Document findings in reports/"
    echo ""
    echo "⚠️  Remember: This is for educational and defensive research only!"
    echo "   Always follow responsible disclosure and ethical guidelines."
}

# Run main function
main "$@"
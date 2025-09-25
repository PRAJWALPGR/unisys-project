package com.example.detection.service

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Threat Intelligence Feed Service
 * Integrates with security sources to make honeypot traps more context-aware and effective.
 */
class ThreatIntelligenceService(private val context: Context) {

    private val TAG = "ThreatIntelService"
    
    // Gson for JSON parsing
    private val gson = Gson()
    
    // Cache storage
    private val processNameCache = ConcurrentHashMap<String, Boolean>()
    private val fileHashCache = ConcurrentHashMap<String, Boolean>()
    private val signatureCache = ConcurrentHashMap<String, Boolean>()
    private val threatRules = ConcurrentHashMap<String, ThreatRule>()
    
    // Tracking last update times
    private val lastUpdateTime = AtomicLong(0)
    
    // Update lock to prevent concurrent updates
    private val isUpdating = AtomicBoolean(false)
    
    // Update frequency settings
    private val updateIntervalHours = 24L  // Default: once per day
    
    // Date formatter for file naming
    private val dateFormatter = SimpleDateFormat("yyyyMMdd", Locale.US)
    
    // Available threat intelligence sources
    private val threatSources = listOf(
        ThreatSource(
            "Common Malware Process Names",
            "https://threatintel.example.com/api/v1/malicious-processes.json",
            ThreatType.PROCESS
        ),
        ThreatSource(
            "Suspicious File Hashes",
            "https://threatintel.example.com/api/v1/suspicious-hashes.json",
            ThreatType.FILE
        ),
        ThreatSource(
            "Clone App Signatures",
            "https://threatintel.example.com/api/v1/clone-app-signatures.json",
            ThreatType.SIGNATURE
        ),
        ThreatSource(
            "Network IOCs",
            "https://threatintel.example.com/api/v1/network-indicators.json",
            ThreatType.NETWORK
        )
    )
    
    init {
        // Load cached threat data on initialization
        loadCachedThreatData()
    }
    
    /**
     * Update threat intelligence data
     */
    fun updateThreatData() {
        // Don't update if already in progress
        if (isUpdating.getAndSet(true)) {
            return
        }
        
        CoroutineScope(Dispatchers.IO).launch {
            try {
                Log.d(TAG, "Starting threat intelligence update")
                
                // Check if update is needed (based on time)
                val currentTime = System.currentTimeMillis()
                val lastUpdate = lastUpdateTime.get()
                val timeSinceUpdate = currentTime - lastUpdate
                
                if (lastUpdate > 0 && timeSinceUpdate < TimeUnit.HOURS.toMillis(updateIntervalHours)) {
                    Log.d(TAG, "Skipping update, last update was ${timeSinceUpdate / 1000 / 60} minutes ago")
                    isUpdating.set(false)
                    return@launch
                }
                
                // In a real app, we would download from actual threat intelligence feeds
                // For demo purposes, we'll create simulated data and store it locally
                generateAndStoreSampleThreatData()
                
                // Update timestamp
                lastUpdateTime.set(currentTime)
                
                // Reload data
                loadCachedThreatData()
                
                Log.d(TAG, "Threat intelligence update completed")
            } catch (e: Exception) {
                Log.e(TAG, "Error updating threat data: ${e.message}")
                e.printStackTrace()
            } finally {
                isUpdating.set(false)
            }
        }
    }
    
    /**
     * Create simulated threat data for demonstration
     */
    private suspend fun generateAndStoreSampleThreatData() = withContext(Dispatchers.IO) {
        val dataDir = File(context.filesDir, "threat_intel")
        if (!dataDir.exists()) {
            dataDir.mkdirs()
        }
        
        val currentDate = dateFormatter.format(Date())
        
        // Sample malicious process names
        val maliciousProcesses = listOf(
            ThreatItem("cryptominer", "High", "Cryptocurrency mining process"),
            ThreatItem("keylogger_service", "Critical", "Keylogging background service"),
            ThreatItem("data_exfil", "High", "Data exfiltration process"),
            ThreatItem("rootkit_manager", "Critical", "Rootkit management process"),
            ThreatItem("remote_access", "High", "Unauthorized remote access tool"),
            ThreatItem("system_hook", "Medium", "System hooking process"),
            ThreatItem("cloner_service", "High", "App cloning service process"),
            ThreatItem("package_spoof", "High", "Package spoofing service")
        )
        val processFile = File(dataDir, "malicious_processes_$currentDate.json")
        processFile.writeText(gson.toJson(maliciousProcesses))
        
        // Sample suspicious file hashes
        val suspiciousHashes = listOf(
            ThreatItem("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "Medium", "Suspicious config file"),
            ThreatItem("d3b07384d113edec49eaa6238ad5ff00", "High", "Known malware hash"),
            ThreatItem("c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", "Critical", "Ransomware payload"),
            ThreatItem("5eb63bbbe01eeed093cb22bb8f5acdc3", "Medium", "Suspicious script")
        )
        val hashFile = File(dataDir, "suspicious_hashes_$currentDate.json")
        hashFile.writeText(gson.toJson(suspiciousHashes))
        
        // Sample app clone signatures
        val cloneSignatures = listOf(
            ThreatItem("com.bank.mobile.modified", "High", "Modified banking app"),
            ThreatItem("com.payment.wallet.cloned", "Critical", "Cloned payment wallet"),
            ThreatItem("com.secure.messenger.fake", "High", "Fake secure messenger"),
            ThreatItem("com.social.network.trojan", "High", "Trojanized social app")
        )
        val signatureFile = File(dataDir, "clone_signatures_$currentDate.json")
        signatureFile.writeText(gson.toJson(cloneSignatures))
        
        // Sample network indicators
        val networkIndicators = listOf(
            ThreatItem("evil.example.com", "High", "Malware command & control"),
            ThreatItem("185.192.69.210", "Critical", "Botnet control server"),
            ThreatItem("data-steal.example.net", "High", "Data exfiltration endpoint"),
            ThreatItem("91.243.62.103", "Medium", "Suspicious mining pool")
        )
        val networkFile = File(dataDir, "network_indicators_$currentDate.json")
        networkFile.writeText(gson.toJson(networkIndicators))
        
        // Sample threat rules
        val rules = listOf(
            ThreatRule(
                "RULE001",
                "Crypto Miner Detection",
                "Identifies cryptocurrency mining activity",
                "HIGH",
                listOf("cryptominer", "miner64", "xmrig"),
                ThreatType.PROCESS,
                "BLOCK",
                System.currentTimeMillis()
            ),
            ThreatRule(
                "RULE002",
                "Data Exfiltration Detection",
                "Identifies data theft activities",
                "CRITICAL",
                listOf("data-steal.example.net", "exfil.example.com"),
                ThreatType.NETWORK,
                "BLOCK_AND_ALERT",
                System.currentTimeMillis()
            ),
            ThreatRule(
                "RULE003",
                "Suspicious Config Access",
                "Detects access to sensitive configuration",
                "MEDIUM",
                listOf("secure/config", "credentials.json"),
                ThreatType.FILE,
                "ALERT",
                System.currentTimeMillis()
            )
        )
        val rulesFile = File(dataDir, "threat_rules_$currentDate.json")
        rulesFile.writeText(gson.toJson(rules))
    }
    
    /**
     * Load cached threat data from local storage
     */
    private fun loadCachedThreatData() {
        try {
            val dataDir = File(context.filesDir, "threat_intel")
            if (!dataDir.exists()) {
                Log.d(TAG, "No cached threat data found")
                return
            }
            
            // Find the latest files for each type
            val processFile = findLatestFile(dataDir, "malicious_processes_")
            val hashFile = findLatestFile(dataDir, "suspicious_hashes_")
            val signatureFile = findLatestFile(dataDir, "clone_signatures_")
            val networkFile = findLatestFile(dataDir, "network_indicators_")
            val rulesFile = findLatestFile(dataDir, "threat_rules_")
            
            // Clear existing caches
            processNameCache.clear()
            fileHashCache.clear()
            signatureCache.clear()
            threatRules.clear()
            
            // Load process names
            processFile?.let { file ->
                val itemType = object : TypeToken<List<ThreatItem>>() {}.type
                val processes: List<ThreatItem> = gson.fromJson(file.readText(), itemType)
                processes.forEach { processNameCache[it.value.lowercase()] = true }
                Log.d(TAG, "Loaded ${processes.size} malicious process patterns")
            }
            
            // Load file hashes
            hashFile?.let { file ->
                val itemType = object : TypeToken<List<ThreatItem>>() {}.type
                val hashes: List<ThreatItem> = gson.fromJson(file.readText(), itemType)
                hashes.forEach { fileHashCache[it.value.lowercase()] = true }
                Log.d(TAG, "Loaded ${hashes.size} suspicious file hashes")
            }
            
            // Load app signatures
            signatureFile?.let { file ->
                val itemType = object : TypeToken<List<ThreatItem>>() {}.type
                val signatures: List<ThreatItem> = gson.fromJson(file.readText(), itemType)
                signatures.forEach { signatureCache[it.value.lowercase()] = true }
                Log.d(TAG, "Loaded ${signatures.size} clone app signatures")
            }
            
            // Load threat rules
            rulesFile?.let { file ->
                val ruleType = object : TypeToken<List<ThreatRule>>() {}.type
                val rules: List<ThreatRule> = gson.fromJson(file.readText(), ruleType)
                rules.forEach { threatRules[it.id] = it }
                Log.d(TAG, "Loaded ${rules.size} threat rules")
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error loading cached threat data: ${e.message}")
            e.printStackTrace()
        }
    }
    
    /**
     * Find the latest file with a given prefix in a directory
     */
    private fun findLatestFile(directory: File, prefix: String): File? {
        val files = directory.listFiles { file ->
            file.isFile && file.name.startsWith(prefix)
        } ?: return null
        
        return files.maxByOrNull { it.lastModified() }
    }
    
    /**
     * Check if a process name matches known malicious patterns
     */
    fun isKnownMaliciousProcess(processName: String): Boolean {
        val lowerName = processName.lowercase()
        
        // Direct match check
        if (processNameCache.containsKey(lowerName)) {
            return true
        }
        
        // Pattern matching check
        return processNameCache.keys.any { pattern -> 
            lowerName.contains(pattern) 
        }
    }
    
    /**
     * Check if a file hash matches known suspicious hashes
     */
    fun isKnownSuspiciousHash(fileHash: String): Boolean {
        return fileHashCache.containsKey(fileHash.lowercase())
    }
    
    /**
     * Check if an app signature matches known clone signatures
     */
    fun isKnownCloneSignature(signature: String): Boolean {
        val lowerSig = signature.lowercase()
        
        // Direct match check
        if (signatureCache.containsKey(lowerSig)) {
            return true
        }
        
        // Pattern matching check
        return signatureCache.keys.any { pattern -> 
            lowerSig.contains(pattern) 
        }
    }
    
    /**
     * Get all active threat rules
     */
    fun getActiveRules(): List<ThreatRule> {
        return threatRules.values.toList()
    }
    
    /**
     * Get last update timestamp
     */
    fun getLastUpdateTime(): Long {
        return lastUpdateTime.get()
    }
    
    /**
     * Check if update is in progress
     */
    fun isUpdating(): Boolean {
        return isUpdating.get()
    }
    
    /**
     * Evaluate a process against relevant threat rules
     */
    fun evaluateProcess(processName: String): RuleMatchResult {
        val matchedRules = mutableListOf<ThreatRule>()
        
        threatRules.values.forEach { rule ->
            if (rule.type == ThreatType.PROCESS) {
                val matches = rule.patterns.any { pattern ->
                    processName.lowercase().contains(pattern.lowercase())
                }
                
                if (matches) {
                    matchedRules.add(rule)
                }
            }
        }
        
        return RuleMatchResult(
            matched = matchedRules.isNotEmpty(),
            rules = matchedRules,
            highestSeverity = matchedRules.maxByOrNull { 
                severityToValue(it.severity) 
            }?.severity ?: "NONE"
        )
    }
    
    /**
     * Evaluate a network target against relevant threat rules
     */
    fun evaluateNetwork(target: String): RuleMatchResult {
        val matchedRules = mutableListOf<ThreatRule>()
        
        threatRules.values.forEach { rule ->
            if (rule.type == ThreatType.NETWORK) {
                val matches = rule.patterns.any { pattern ->
                    target.lowercase().contains(pattern.lowercase())
                }
                
                if (matches) {
                    matchedRules.add(rule)
                }
            }
        }
        
        return RuleMatchResult(
            matched = matchedRules.isNotEmpty(),
            rules = matchedRules,
            highestSeverity = matchedRules.maxByOrNull { 
                severityToValue(it.severity) 
            }?.severity ?: "NONE"
        )
    }
    
    /**
     * Evaluate a file path against relevant threat rules
     */
    fun evaluateFile(filePath: String): RuleMatchResult {
        val matchedRules = mutableListOf<ThreatRule>()
        
        threatRules.values.forEach { rule ->
            if (rule.type == ThreatType.FILE) {
                val matches = rule.patterns.any { pattern ->
                    filePath.lowercase().contains(pattern.lowercase())
                }
                
                if (matches) {
                    matchedRules.add(rule)
                }
            }
        }
        
        return RuleMatchResult(
            matched = matchedRules.isNotEmpty(),
            rules = matchedRules,
            highestSeverity = matchedRules.maxByOrNull { 
                severityToValue(it.severity) 
            }?.severity ?: "NONE"
        )
    }
    
    /**
     * Convert severity string to numeric value for comparison
     */
    private fun severityToValue(severity: String): Int {
        return when (severity.uppercase()) {
            "CRITICAL" -> 4
            "HIGH" -> 3
            "MEDIUM" -> 2
            "LOW" -> 1
            else -> 0
        }
    }
    
    /**
     * Create new threat-aware honeypot traps based on threat intelligence
     */
    fun createThreatAwareTraps(cloneDetectionService: CloneDetectionService): List<String> {
        val createdTraps = mutableListOf<String>()
        
        try {
            // Create traps based on process threats
            val processRules = threatRules.values.filter { it.type == ThreatType.PROCESS }
            processRules.forEach { rule ->
                rule.patterns.forEach { pattern ->
                    val trapId = cloneDetectionService.addTrap(
                        "ThreatIntel: ${rule.name}",
                        CloneDetectionService.TrapType.PROCESS,
                        pattern,
                        when (rule.severity) {
                            "CRITICAL", "HIGH" -> CloneDetectionService.AlertLevel.HIGH
                            "MEDIUM" -> CloneDetectionService.AlertLevel.MEDIUM
                            else -> CloneDetectionService.AlertLevel.LOW
                        },
                        "Created by Threat Intelligence: ${rule.description}"
                    )
                    createdTraps.add(trapId)
                }
            }
            
            // Create traps based on network threats
            val networkRules = threatRules.values.filter { it.type == ThreatType.NETWORK }
            networkRules.forEach { rule ->
                rule.patterns.forEach { pattern ->
                    if (pattern.matches("\\d+\\.\\d+\\.\\d+\\.\\d+".toRegex())) {
                        // IP address - not ideal for port-based traps
                        // In a real implementation, we'd create a network traffic monitoring trap
                    } else if (pattern.matches("\\d+".toRegex())) {
                        // Looks like a port number
                        val trapId = cloneDetectionService.addTrap(
                            "ThreatIntel: ${rule.name}",
                            CloneDetectionService.TrapType.NETWORK,
                            pattern,
                            when (rule.severity) {
                                "CRITICAL", "HIGH" -> CloneDetectionService.AlertLevel.HIGH
                                "MEDIUM" -> CloneDetectionService.AlertLevel.MEDIUM
                                else -> CloneDetectionService.AlertLevel.LOW
                            },
                            "Created by Threat Intelligence: ${rule.description}"
                        )
                        createdTraps.add(trapId)
                    }
                }
            }
            
            // Create traps based on file threats
            val fileRules = threatRules.values.filter { it.type == ThreatType.FILE }
            fileRules.forEach { rule ->
                rule.patterns.forEach { pattern ->
                    if (pattern.contains("/") || pattern.contains("\\")) {
                        // Looks like a path
                        val trapId = cloneDetectionService.addTrap(
                            "ThreatIntel: ${rule.name}",
                            CloneDetectionService.TrapType.FILE,
                            pattern,
                            when (rule.severity) {
                                "CRITICAL", "HIGH" -> CloneDetectionService.AlertLevel.HIGH
                                "MEDIUM" -> CloneDetectionService.AlertLevel.MEDIUM
                                else -> CloneDetectionService.AlertLevel.LOW
                            },
                            "Created by Threat Intelligence: ${rule.description}"
                        )
                        createdTraps.add(trapId)
                    }
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error creating threat-aware traps: ${e.message}")
            e.printStackTrace()
        }
        
        return createdTraps
    }
    
    /**
     * Data class representing a threat intelligence source
     */
    data class ThreatSource(
        val name: String,
        val url: String,
        val type: ThreatType
    )
    
    /**
     * Data class representing a threat intelligence item
     */
    data class ThreatItem(
        val value: String,
        val severity: String,
        val description: String
    )
    
    /**
     * Data class representing a threat rule
     */
    data class ThreatRule(
        val id: String,
        val name: String,
        val description: String,
        val severity: String,
        val patterns: List<String>,
        val type: ThreatType,
        val action: String,
        val created: Long
    )
    
    /**
     * Data class for rule matching results
     */
    data class RuleMatchResult(
        val matched: Boolean,
        val rules: List<ThreatRule>,
        val highestSeverity: String
    )
    
    /**
     * Enum for types of threat intelligence data
     */
    enum class ThreatType {
        PROCESS,
        NETWORK,
        FILE,
        SIGNATURE
    }
} 
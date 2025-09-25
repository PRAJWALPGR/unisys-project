package com.example.detection.honeypot.emotiontrap

import android.content.Context
import android.util.Log
import com.example.detection.service.BlockchainScanService
import com.example.detection.service.CloneDetectionService
import com.example.detection.service.TrapInteractionRecorder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/**
 * Manager class that connects the Emotional Deception Environment (EDE) with the rest of the application.
 * Serves as the main integration point between the EDE and other services.
 */
class EmotionalDeceptionManager(
    private val context: Context,
    private val trapInteractionRecorder: TrapInteractionRecorder,
    private val blockchainScanService: BlockchainScanService? = null
) {
    private val TAG = "EmotionalDeceptionMgr"
    private val managerScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    
    // The main service
    private lateinit var edeService: EmotionalDeceptionEnvironmentService
    
    // Pattern analyzer for emotional behavior analysis
    private lateinit var patternAnalyzer: EmotionalPatternAnalyzer
    
    // Last scan results
    private val _scanResults = MutableStateFlow<Map<String, Any>>(emptyMap())
    val scanResults: StateFlow<Map<String, Any>> = _scanResults
    
    // Settings controls
    private var enabled = true

    /**
     * Initialize the manager and related services
     */
    fun initialize() {
        Log.d(TAG, "Initializing Emotional Deception Manager")
        
        // Initialize the pattern analyzer
        patternAnalyzer = EmotionalPatternAnalyzer(context)
        
        // Initialize the EDE service
        edeService = EmotionalDeceptionEnvironmentService(context, trapInteractionRecorder)
        edeService.initialize()
        
        // Observe the service state
        managerScope.launch {
            edeService.isActive.collect { isActive ->
                Log.d(TAG, "EDE service active state changed: $isActive")
                // Update scan results when service state changes
                updateScanResults()
            }
        }
        
        // Observe suspicious activities
        managerScope.launch {
            edeService.detectedActivities.collect { activities ->
                if (activities.isNotEmpty()) {
                    Log.w(TAG, "New suspicious activities detected: ${activities.size}")
                    
                    // Send to blockchain if available (only for critical/high severity)
                    val criticalActivities = activities.filter { 
                        it.severity == EmotionalDeceptionEnvironmentService.ThreatSeverity.CRITICAL ||
                        it.severity == EmotionalDeceptionEnvironmentService.ThreatSeverity.HIGH
                    }
                    
                    if (criticalActivities.isNotEmpty() && blockchainScanService != null) {
                        for (activity in criticalActivities) {
                            val event = mapOf(
                                "id" to activity.id,
                                "type" to activity.type.toString(),
                                "description" to activity.description,
                                "severity" to activity.severity.toString(),
                                "timestamp" to activity.timestamp
                            )
                            
                            try {
                                // This method doesn't exist in BlockchainScanService
                                // Replace with appropriate logging until the method is implemented
                                Log.d(TAG, "Would record suspicious activity in blockchain: ${activity.id}")
                                Log.d(TAG, "Activity details: $event")
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to record in blockchain: ${e.message}")
                            }
                        }
                    }
                    
                    // Update scan results
                    updateScanResults()
                }
            }
        }
    }
    
    /**
     * Start the Emotional Deception Environment service
     */
    fun startService() {
        if (!::edeService.isInitialized) {
            Log.e(TAG, "Cannot start service, manager not initialized")
            return
        }
        
        edeService.startService()
        Log.d(TAG, "EDE service started")
    }
    
    /**
     * Stop the Emotional Deception Environment service
     */
    fun stopService() {
        if (!::edeService.isInitialized) {
            Log.e(TAG, "Cannot stop service, manager not initialized")
            return
        }
        
        edeService.stopService()
        Log.d(TAG, "EDE service stopped")
    }
    
    /**
     * Get the service active state
     */
    fun isServiceActive(): Boolean {
        return if (::edeService.isInitialized) {
            edeService.isActive.value
        } else {
            false
        }
    }
    
    /**
     * Create a new emotional trap
     */
    fun createEmotionalTrap(
        name: String,
        emotionalState: EmotionalDeceptionEnvironmentService.EmotionalState,
        description: String
    ): String? {
        return if (::edeService.isInitialized) {
            val trapId = edeService.createEmotionalTrap(name, emotionalState, description)
            Log.d(TAG, "Created new emotional trap: $name (ID: $trapId)")
            trapId
        } else {
            Log.e(TAG, "Cannot create trap, manager not initialized")
            null
        }
    }
    
    /**
     * Get all active emotional traps
     */
    fun getActiveTraps(): List<EmotionalDeceptionEnvironmentService.EmotionalTrap> {
        return if (::edeService.isInitialized) {
            edeService.getActiveTraps()
        } else {
            emptyList()
        }
    }
    
    /**
     * Get recent emotional trap activities
     */
    fun getRecentActivities(): List<EmotionalDeceptionEnvironmentService.EmotionalTrapActivity> {
        return if (::edeService.isInitialized) {
            edeService.trapActivity.value ?: emptyList()
        } else {
            emptyList()
        }
    }
    
    /**
     * Get detected suspicious activities
     */
    fun getDetectedActivities(): List<EmotionalDeceptionEnvironmentService.SuspiciousActivity> {
        return if (::edeService.isInitialized) {
            edeService.detectedActivities.value
        } else {
            emptyList()
        }
    }
    
    /**
     * Perform a scan of the emotional deception environment
     */
    fun performScan(): Map<String, Any> {
        // Check if service is enabled
        if (!enabled) {
            return mapOf(
                "status" to "disabled",
                "message" to "Emotional Deception Environment is disabled in settings"
            )
        }
        
        // Perform the scan
        val scanResults = mutableMapOf<String, Any>()
        
        if (!::edeService.isInitialized) {
            Log.e(TAG, "Cannot perform scan, manager not initialized")
            return scanResults
        }
        
        val results = edeService.getScanResults()
        _scanResults.value = results
        
        Log.d(TAG, "EDE scan completed with ${results.size} result fields")
        return results
    }
    
    /**
     * Update scan results
     */
    private fun updateScanResults() {
        if (::edeService.isInitialized) {
            val results = edeService.getScanResults()
            _scanResults.value = results
        }
    }
    
    /**
     * Generate emotionally modified text based on the given emotional state
     */
    fun generateEmotionalText(
        emotionalState: EmotionalDeceptionEnvironmentService.EmotionalState,
        baseText: String
    ): String {
        return if (::patternAnalyzer.isInitialized) {
            patternAnalyzer.generateEmotionalTypingPattern(emotionalState, baseText)
        } else {
            baseText
        }
    }
    
    /**
     * Analyze interactions for anomalous patterns
     */
    fun analyzeInteractions(
        interactions: List<EmotionalDeceptionEnvironmentService.TrapInteraction>
    ): EmotionalPatternAnalyzer.EmotionalAnalysisResult {
        return if (::patternAnalyzer.isInitialized) {
            patternAnalyzer.analyzeInteractions(interactions)
        } else {
            EmotionalPatternAnalyzer.EmotionalAnalysisResult(
                detectedPatterns = emptyList(),
                anomalyScore = 0.0f,
                confidenceLevel = 0.0f
            )
        }
    }
    
    /**
     * Cleanup resources
     */
    fun cleanup() {
        if (::edeService.isInitialized) {
            edeService.cleanup()
        }
    }

    /**
     * Enable or disable the emotional deception environment.
     */
    fun setEnabled(enabled: Boolean) {
        this.enabled = enabled
        if (enabled) {
            activateDeceptionSystem()
        } else {
            deactivateDeceptionSystem()
        }
    }

    private fun activateDeceptionSystem() {
        // Implementation to activate the deception system
    }

    private fun deactivateDeceptionSystem() {
        // Implementation to deactivate the deception system
    }
} 
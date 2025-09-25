package com.example.detection.honeypot.emotiontrap

import android.content.Context
import android.util.Log
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.example.detection.service.BlockchainScanService
import com.example.detection.service.CloneDetectionService
import com.example.detection.service.TrapInteractionRecorder
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

/**
 * Emotional Deception Environment (EDE) Service
 * 
 * A honeypot trap module that simulates emotionally charged user behavior
 * to bait emotion-aware malware into revealing itself.
 */
class EmotionalDeceptionEnvironmentService(
    private val context: Context,
    private val trapInteractionRecorder: TrapInteractionRecorder
) {
    private val TAG = "EmotionalDeceptionEnv"
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    
    // Active emotional traps
    private val activeEmotionalTraps = ConcurrentHashMap<String, EmotionalTrap>()
    
    // Service state
    private val _isActive = MutableStateFlow(false)
    val isActive: StateFlow<Boolean> = _isActive.asStateFlow()
    
    // Emotional trap activity
    private val _trapActivity = MutableLiveData<List<EmotionalTrapActivity>>(emptyList())
    val trapActivity: LiveData<List<EmotionalTrapActivity>> = _trapActivity
    
    // Detected suspicious activities
    private val _detectedActivities = MutableStateFlow<List<SuspiciousActivity>>(emptyList())
    val detectedActivities: StateFlow<List<SuspiciousActivity>> = _detectedActivities
    
    // Emotional personas for simulation
    private val emotionalPersonas = listOf(
        EmotionalPersona("Anxious User", EmotionalState.ANXIETY),
        EmotionalPersona("Frustrated User", EmotionalState.FRUSTRATION),
        EmotionalPersona("Urgent User", EmotionalState.URGENCY),
        EmotionalPersona("Angry User", EmotionalState.ANGER),
        EmotionalPersona("Financial Stress", EmotionalState.FINANCIAL_STRESS),
        EmotionalPersona("Personal Crisis", EmotionalState.PERSONAL_CRISIS)
    )
    
    /**
     * Initialize the Emotional Deception Environment service
     */
    fun initialize() {
        Log.d(TAG, "Initializing Emotional Deception Environment service")
        
        // Setup default emotional traps
        setupDefaultTraps()
    }
    
    /**
     * Start the Emotional Deception Environment
     */
    fun startService() {
        if (_isActive.value) {
            Log.d(TAG, "EDE service is already active")
            return
        }
        
        Log.d(TAG, "Starting Emotional Deception Environment")
        _isActive.value = true
        
        // Start monitoring for suspicious activities
        serviceScope.launch {
            monitorSuspiciousActivities()
        }
    }
    
    /**
     * Stop the Emotional Deception Environment
     */
    fun stopService() {
        if (!_isActive.value) {
            Log.d(TAG, "EDE service is already inactive")
            return
        }
        
        Log.d(TAG, "Stopping Emotional Deception Environment")
        _isActive.value = false
    }
    
    /**
     * Create a new emotional trap
     * 
     * @param name The name of the trap
     * @param emotionalState The emotional state to simulate
     * @param description Description of the trap
     * @return The ID of the created trap
     */
    fun createEmotionalTrap(
        name: String,
        emotionalState: EmotionalState,
        description: String
    ): String {
        val trapId = UUID.randomUUID().toString()
        
        val trap = EmotionalTrap(
            id = trapId,
            name = name,
            emotionalState = emotionalState,
            description = description,
            creationTimestamp = System.currentTimeMillis(),
            isActive = true,
            interactions = mutableListOf()
        )
        
        activeEmotionalTraps[trapId] = trap
        Log.d(TAG, "Created emotional trap: $name (ID: $trapId)")
        
        // Generate initial simulated interactions
        simulateEmotionalInteractions(trap)
        
        return trapId
    }
    
    /**
     * Setup default emotional traps
     */
    private fun setupDefaultTraps() {
        createEmotionalTrap(
            "Financial Urgency",
            EmotionalState.FINANCIAL_STRESS,
            "Simulates urgent financial transactions and banking activities during stress"
        )
        
        createEmotionalTrap(
            "Personal Crisis Communication",
            EmotionalState.PERSONAL_CRISIS,
            "Simulates communication patterns during personal emergency situations"
        )
        
        createEmotionalTrap(
            "Anxiety-Driven Search Patterns",
            EmotionalState.ANXIETY,
            "Simulates anxious search behavior and information gathering"
        )
    }
    
    /**
     * Simulate emotional interactions for a trap
     */
    private fun simulateEmotionalInteractions(trap: EmotionalTrap) {
        serviceScope.launch {
            val interactionCount = Random.nextInt(3, 10)
            val currentTime = System.currentTimeMillis()
            
            val simInteractions = mutableListOf<TrapInteraction>()
            
            for (i in 0 until interactionCount) {
                val timeOffset = Random.nextLong(1000, 3600000) // Between 1 second and 1 hour
                val timestamp = currentTime - timeOffset
                
                val interaction = when (trap.emotionalState) {
                    EmotionalState.FINANCIAL_STRESS -> generateFinancialStressInteraction(timestamp)
                    EmotionalState.ANXIETY -> generateAnxietyInteraction(timestamp)
                    EmotionalState.URGENCY -> generateUrgencyInteraction(timestamp)
                    EmotionalState.FRUSTRATION -> generateFrustrationInteraction(timestamp)
                    EmotionalState.ANGER -> generateAngerInteraction(timestamp)
                    EmotionalState.PERSONAL_CRISIS -> generatePersonalCrisisInteraction(timestamp)
                }
                
                simInteractions.add(interaction)
            }
            
            // Sort by timestamp (newest first)
            simInteractions.sortByDescending { it.timestamp }
            
            // Update the trap with the simulated interactions
            trap.interactions.addAll(simInteractions)
            
            // Record the simulated interactions
            recordTrapInteractions(trap.id, simInteractions)
        }
    }
    
    /**
     * Generate a financial stress interaction
     */
    private fun generateFinancialStressInteraction(timestamp: Long): TrapInteraction {
        val actions = listOf(
            "Rapid bank login attempt",
            "Urgent money transfer form filled",
            "Multiple account balance checks",
            "Cryptocurrency wallet access",
            "Payment deadline extension search",
            "Loan application started",
            "Credit score check"
        )
        
        return TrapInteraction(
            id = UUID.randomUUID().toString(),
            action = actions.random(),
            timestamp = timestamp,
            metadata = mapOf(
                "typing_speed" to "faster than normal",
                "error_rate" to "high",
                "urgency_indicators" to "true",
                "amount_pattern" to "large_sum"
            )
        )
    }
    
    /**
     * Generate an anxiety interaction
     */
    private fun generateAnxietyInteraction(timestamp: Long): TrapInteraction {
        val actions = listOf(
            "Repeated form submission attempts",
            "Multiple navigation path changes",
            "Rapid scrolling pattern detected",
            "Hesitant input with multiple corrections",
            "Health symptom search",
            "Security settings checked repeatedly"
        )
        
        return TrapInteraction(
            id = UUID.randomUUID().toString(),
            action = actions.random(),
            timestamp = timestamp,
            metadata = mapOf(
                "cursor_movement" to "erratic",
                "dwell_time" to "short",
                "repeated_actions" to "true",
                "input_correction_rate" to "high"
            )
        )
    }
    
    /**
     * Generate an urgency interaction
     */
    private fun generateUrgencyInteraction(timestamp: Long): TrapInteraction {
        val actions = listOf(
            "Time-sensitive form submission",
            "Quick navigation through critical paths",
            "Deadline-related search query",
            "Emergency contact information accessed",
            "Location services activated"
        )
        
        return TrapInteraction(
            id = UUID.randomUUID().toString(),
            action = actions.random(),
            timestamp = timestamp,
            metadata = mapOf(
                "completion_speed" to "very_fast",
                "time_expressions" to "frequent",
                "shortcut_usage" to "high",
                "validation_skipping" to "attempted"
            )
        )
    }
    
    /**
     * Generate a frustration interaction
     */
    private fun generateFrustrationInteraction(timestamp: Long): TrapInteraction {
        val actions = listOf(
            "Repeated button clicking",
            "Form resubmission after error",
            "Navigation back-and-forth",
            "Help/FAQ section access",
            "Abandoned transaction"
        )
        
        return TrapInteraction(
            id = UUID.randomUUID().toString(),
            action = actions.random(),
            timestamp = timestamp,
            metadata = mapOf(
                "click_frequency" to "high",
                "input_force" to "strong",
                "session_restarts" to "multiple",
                "error_encounters" to "frequent"
            )
        )
    }
    
    /**
     * Generate an anger interaction
     */
    private fun generateAngerInteraction(timestamp: Long): TrapInteraction {
        val actions = listOf(
            "Complaint form filled",
            "Support chat initiated",
            "Negative review drafted",
            "Account deletion attempted",
            "ALL CAPS TEXT INPUT"
        )
        
        return TrapInteraction(
            id = UUID.randomUUID().toString(),
            action = actions.random(),
            timestamp = timestamp,
            metadata = mapOf(
                "caps_lock_usage" to "frequent",
                "punctuation_pattern" to "excessive",
                "negative_language" to "detected",
                "form_abandon_rate" to "high"
            )
        )
    }
    
    /**
     * Generate a personal crisis interaction
     */
    private fun generatePersonalCrisisInteraction(timestamp: Long): TrapInteraction {
        val actions = listOf(
            "Emergency contact information accessed",
            "Crisis hotline search",
            "Medical symptoms search",
            "Hospital location query",
            "Insurance policy access",
            "Legal document generation"
        )
        
        return TrapInteraction(
            id = UUID.randomUUID().toString(),
            action = actions.random(),
            timestamp = timestamp,
            metadata = mapOf(
                "time_sensitivity" to "critical",
                "location_services" to "activated",
                "privacy_sensitive" to "highly",
                "medical_terms" to "present"
            )
        )
    }
    
    /**
     * Record trap interactions with the TrapInteractionRecorder
     */
    private fun recordTrapInteractions(trapId: String, interactions: List<TrapInteraction>) {
        interactions.forEach { interaction ->
            trapInteractionRecorder.recordInteraction(
                trapId = "ede_$trapId",
                trapType = CloneDetectionService.TrapType.NETWORK,
                trapName = "Emotional Trap",
                action = TrapInteractionRecorder.InteractionType.CUSTOM_ACCESS,
                packageName = context.packageName,
                metadata = interaction.metadata
            )
            
            // Hash and add to blockchain if severe emotional state
            val trap = activeEmotionalTraps[trapId]
            if (trap != null && isHighSeverityEmotionalState(trap.emotionalState)) {
                val interactionData = Gson().toJson(interaction)
                val hash = hashInteractionData(interactionData)
                
                // Send to blockchain (this would be handled by your existing BlockchainScanService)
                // In a real implementation, you would inject this service
                serviceScope.launch {
                    try {
                        // This is a placeholder - in actual implementation you'd call your blockchain service
                        Log.d(TAG, "Sending interaction hash to blockchain: $hash")
                        // blockchainScanService.recordEvent("ede_interaction", hash)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error sending to blockchain: ${e.message}")
                    }
                }
            }
        }
        
        // Update the activity LiveData with new data
        updateTrapActivity()
    }
    
    /**
     * Hash interaction data for blockchain storage
     */
    private fun hashInteractionData(data: String): String {
        val bytes = MessageDigest.getInstance("SHA-256").digest(data.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }
    
    /**
     * Check if the emotional state is considered high severity
     */
    private fun isHighSeverityEmotionalState(state: EmotionalState): Boolean {
        return when (state) {
            EmotionalState.FINANCIAL_STRESS, 
            EmotionalState.PERSONAL_CRISIS, 
            EmotionalState.URGENCY -> true
            else -> false
        }
    }
    
    /**
     * Update the trap activity LiveData
     */
    private fun updateTrapActivity() {
        val activities = mutableListOf<EmotionalTrapActivity>()
        
        activeEmotionalTraps.values.forEach { trap ->
            trap.interactions.forEach { interaction ->
                activities.add(
                    EmotionalTrapActivity(
                        trapId = trap.id,
                        trapName = trap.name,
                        emotionalState = trap.emotionalState,
                        action = interaction.action,
                        timestamp = interaction.timestamp,
                        metadata = interaction.metadata
                    )
                )
            }
        }
        
        // Sort by timestamp (newest first)
        activities.sortByDescending { it.timestamp }
        
        _trapActivity.postValue(activities)
    }
    
    /**
     * Monitor for suspicious activities related to emotional traps
     */
    private fun monitorSuspiciousActivities() {
        serviceScope.launch {
            while (_isActive.value) {
                // Check for suspicious patterns related to device sensors
                detectSensorActivation()
                
                // Check for screen captures during emotional sessions
                detectScreenCaptures()
                
                // Check for microphone/camera access during emotional sessions
                detectAudioVisualAccess()
                
                kotlinx.coroutines.delay(5000) // Check every 5 seconds
            }
        }
    }
    
    /**
     * Detect sensor activation during emotional trap interactions
     */
    private fun detectSensorActivation() {
        // This is a placeholder implementation
        // In a real app, you would integrate with Android's sensor monitoring APIs
        val sensorActive = Random.nextInt(0, 20) == 0 // Simulate rare detection events
        
        if (sensorActive && _isActive.value) {
            val activity = SuspiciousActivity(
                id = UUID.randomUUID().toString(),
                type = SuspiciousActivityType.SENSOR_ACTIVATION,
                timestamp = System.currentTimeMillis(),
                description = "Unusual sensor activation during emotional interaction",
                severity = ThreatSeverity.MEDIUM
            )
            
            addDetectedActivity(activity)
        }
    }
    
    /**
     * Detect screen captures during emotional sessions
     */
    private fun detectScreenCaptures() {
        // This is a placeholder implementation
        // In a real app, you would integrate with Android's screenshot detection
        val screenCaptureDetected = Random.nextInt(0, 50) == 0 // Simulate rare detection events
        
        if (screenCaptureDetected && _isActive.value) {
            val activity = SuspiciousActivity(
                id = UUID.randomUUID().toString(),
                type = SuspiciousActivityType.SCREEN_CAPTURE,
                timestamp = System.currentTimeMillis(),
                description = "Screen capture detected during simulated emotional stress",
                severity = ThreatSeverity.HIGH
            )
            
            addDetectedActivity(activity)
        }
    }
    
    /**
     * Detect microphone or camera access during emotional sessions
     */
    private fun detectAudioVisualAccess() {
        // This is a placeholder implementation
        // In a real app, you would integrate with Android's camera/mic usage APIs
        val micAccessDetected = Random.nextInt(0, 100) == 0 // Simulate rare detection events
        
        if (micAccessDetected && _isActive.value) {
            val activity = SuspiciousActivity(
                id = UUID.randomUUID().toString(),
                type = SuspiciousActivityType.MICROPHONE_ACCESS,
                timestamp = System.currentTimeMillis(),
                description = "Microphone activated during emotionally sensitive interaction",
                severity = ThreatSeverity.CRITICAL
            )
            
            addDetectedActivity(activity)
        }
    }
    
    /**
     * Add a detected suspicious activity to the list
     */
    private fun addDetectedActivity(activity: SuspiciousActivity) {
        val currentList = _detectedActivities.value.toMutableList()
        currentList.add(0, activity) // Add to the beginning of the list
        _detectedActivities.value = currentList
        
        // Log the activity
        Log.w(TAG, "Suspicious activity detected: ${activity.description} (${activity.type})")
        
        // Record in the trap interaction recorder
        trapInteractionRecorder.recordInteraction(
            trapId = "ede_suspicious_${activity.id}",
            trapType = CloneDetectionService.TrapType.NETWORK,
            trapName = "EDE Suspicious Activity",
            action = TrapInteractionRecorder.InteractionType.CUSTOM_ACCESS,
            packageName = context.packageName,
            metadata = mapOf(
                "description" to activity.description,
                "severity" to activity.severity.toString(),
                "type" to activity.type.toString()
            )
        )
    }
    
    /**
     * Get all active emotional traps
     */
    fun getActiveTraps(): List<EmotionalTrap> {
        return activeEmotionalTraps.values.filter { it.isActive }.toList()
    }
    
    /**
     * Get a specific emotional trap by ID
     */
    fun getTrap(trapId: String): EmotionalTrap? {
        return activeEmotionalTraps[trapId]
    }
    
    /**
     * Get the scan results for the Emotional Deception Environment
     */
    fun getScanResults(): Map<String, Any> {
        val results = mutableMapOf<String, Any>()
        
        results["ede_active"] = _isActive.value
        results["trap_count"] = activeEmotionalTraps.size
        results["active_trap_count"] = getActiveTraps().size
        
        // Count interactions and suspicious activities
        var totalInteractions = 0
        activeEmotionalTraps.values.forEach { trap ->
            totalInteractions += trap.interactions.size
        }
        
        results["total_interactions"] = totalInteractions
        results["suspicious_activities"] = _detectedActivities.value.size
        
        // Threat assessment
        val threatLevel = when {
            _detectedActivities.value.any { it.severity == ThreatSeverity.CRITICAL } -> "CRITICAL"
            _detectedActivities.value.any { it.severity == ThreatSeverity.HIGH } -> "HIGH"
            _detectedActivities.value.any { it.severity == ThreatSeverity.MEDIUM } -> "MEDIUM"
            _detectedActivities.value.isNotEmpty() -> "LOW"
            else -> "NONE"
        }
        
        results["threat_level"] = threatLevel
        
        // List of detected activities
        val detectionsMap = _detectedActivities.value.map { activity ->
            mapOf(
                "id" to activity.id,
                "type" to activity.type.toString(),
                "timestamp" to activity.timestamp,
                "description" to activity.description,
                "severity" to activity.severity.toString()
            )
        }
        
        results["detected_activities"] = detectionsMap
        
        return results
    }
    
    /**
     * Cleanup resources
     */
    fun cleanup() {
        stopService()
    }
    
    /**
     * Enumeration of emotional states that can be simulated
     */
    enum class EmotionalState {
        @SerializedName("anxiety")
        ANXIETY,
        
        @SerializedName("frustration")
        FRUSTRATION,
        
        @SerializedName("urgency")
        URGENCY,
        
        @SerializedName("anger")
        ANGER,
        
        @SerializedName("financial_stress")
        FINANCIAL_STRESS,
        
        @SerializedName("personal_crisis")
        PERSONAL_CRISIS
    }
    
    /**
     * Enumeration of suspicious activity types
     */
    enum class SuspiciousActivityType {
        SENSOR_ACTIVATION,
        SCREEN_CAPTURE,
        MICROPHONE_ACCESS,
        CAMERA_ACCESS,
        KEYSTROKE_LOGGING,
        UNUSUAL_NETWORK_ACTIVITY
    }
    
    /**
     * Enumeration of threat severity levels
     */
    enum class ThreatSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
    
    /**
     * Data class representing an emotional persona
     */
    data class EmotionalPersona(
        val name: String,
        val emotionalState: EmotionalState
    )
    
    /**
     * Data class representing an emotional trap
     */
    data class EmotionalTrap(
        val id: String,
        val name: String,
        val emotionalState: EmotionalState,
        val description: String,
        val creationTimestamp: Long,
        var isActive: Boolean,
        val interactions: MutableList<TrapInteraction>
    )
    
    /**
     * Data class representing a trap interaction
     */
    data class TrapInteraction(
        val id: String,
        val action: String,
        val timestamp: Long,
        val metadata: Map<String, String>
    )
    
    /**
     * Data class representing emotional trap activity
     */
    data class EmotionalTrapActivity(
        val trapId: String,
        val trapName: String,
        val emotionalState: EmotionalState,
        val action: String,
        val timestamp: Long,
        val metadata: Map<String, String>
    )
    
    /**
     * Data class representing a suspicious activity
     */
    data class SuspiciousActivity(
        val id: String,
        val type: SuspiciousActivityType,
        val timestamp: Long,
        val description: String,
        val severity: ThreatSeverity
    )
} 
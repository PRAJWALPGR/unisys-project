package com.example.detection.service

import android.content.Context
import java.util.LinkedList
import java.util.Queue
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.sqrt
import java.time.Instant
import kotlin.random.Random

/**
 * AI-Powered Behavior Analysis Engine for Honeypot Traps
 * Uses lightweight ML techniques to analyze trap access patterns and identify suspicious behavior
 */
class HoneypotAIEngine(private val context: Context) {

    // Store access history for each trap
    private val accessHistory = ConcurrentHashMap<String, Queue<AccessEvent>>()
    
    // Store anomaly scores for each trap
    private val anomalyScores = ConcurrentHashMap<String, Double>()
    
    // Maximum history size to maintain per trap
    private val MAX_HISTORY_SIZE = 50
    
    // Threshold for determining anomalous behavior
    private val ANOMALY_THRESHOLD = 0.7
    
    // Features extracted from access patterns
    private val featureVectors = ConcurrentHashMap<String, DoubleArray>()
    
    /**
     * Record a new trap access event and analyze it
     */
    fun recordTrapAccess(trapId: String, trapType: CloneDetectionService.TrapType, timestamp: Long = System.currentTimeMillis()): AccessAnalysis {
        // Create event
        val event = AccessEvent(
            trapId = trapId,
            trapType = trapType,
            timestamp = timestamp
        )
        
        // Get or create history queue for this trap
        val history = accessHistory.getOrPut(trapId) { LinkedList() }
        
        // Add event to history, removing oldest if needed
        if (history.size >= MAX_HISTORY_SIZE) {
            history.poll()
        }
        history.add(event)
        
        // Extract features from access pattern
        val features = extractFeatures(trapId, history)
        featureVectors[trapId] = features
        
        // Calculate anomaly score
        val score = calculateAnomalyScore(features)
        anomalyScores[trapId] = score
        
        // Classify if this is suspicious
        val isSuspicious = score > ANOMALY_THRESHOLD
        
        return AccessAnalysis(
            trapId = trapId,
            anomalyScore = score,
            isSuspicious = isSuspicious,
            confidence = calculateConfidence(score),
            features = features.toList(),
            suggestedAction = if (isSuspicious) {
                when {
                    score > 0.9 -> SuggestedAction.BLOCK_AND_ALERT
                    score > 0.8 -> SuggestedAction.INCREASE_MONITORING
                    else -> SuggestedAction.FLAG_FOR_REVIEW
                }
            } else {
                SuggestedAction.NORMAL_OPERATION
            }
        )
    }
    
    /**
     * Extract features from the access history pattern
     */
    private fun extractFeatures(trapId: String, history: Queue<AccessEvent>): DoubleArray {
        if (history.size < 2) {
            return doubleArrayOf(0.0, 0.0, 0.0, 0.0, 0.5)
        }
        
        val events = history.toList()
        
        // Feature 1: Access frequency (accesses per hour)
        val oldestTimestamp = events.first().timestamp
        val newestTimestamp = events.last().timestamp
        val timeSpanHours = (newestTimestamp - oldestTimestamp) / (1000.0 * 60 * 60)
        val frequency = if (timeSpanHours > 0) events.size / timeSpanHours else 10.0
        
        // Feature 2: Variance in time between accesses
        val timeDiffs = mutableListOf<Double>()
        for (i in 1 until events.size) {
            timeDiffs.add((events[i].timestamp - events[i-1].timestamp).toDouble())
        }
        val avgTimeDiff = timeDiffs.average()
        val variance = timeDiffs.map { (it - avgTimeDiff) * (it - avgTimeDiff) }.average()
        val stdDev = sqrt(variance)
        val normalizedStdDev = stdDev / avgTimeDiff
        
        // Feature 3: Time of day pattern (0-1 representing 24h cycle)
        val timeOfDayDistribution = events.map { (it.timestamp % (24 * 60 * 60 * 1000)) / (24.0 * 60 * 60 * 1000) }
        val timeOfDayVariance = calculateCircularVariance(timeOfDayDistribution)
        
        // Feature 4: Burst detection (rapid sequential access)
        val burstRatio = timeDiffs.count { it < 1000 }.toDouble() / timeDiffs.size
        
        // Feature 5: Access pattern predictability
        val patternPredictability = calculatePatternPredictability(timeDiffs)
        
        return doubleArrayOf(
            normalizeFeature(frequency, 0.0, 100.0),
            normalizeFeature(normalizedStdDev, 0.0, 2.0),
            timeOfDayVariance,
            burstRatio,
            patternPredictability
        )
    }
    
    /**
     * Calculate circular variance for time-of-day analysis
     */
    private fun calculateCircularVariance(values: List<Double>): Double {
        if (values.isEmpty()) return 0.5
        
        val n = values.size
        var sinSum = 0.0
        var cosSum = 0.0
        
        for (v in values) {
            val angle = v * 2 * Math.PI
            sinSum += Math.sin(angle)
            cosSum += Math.cos(angle)
        }
        
        val r = sqrt((sinSum * sinSum + cosSum * cosSum) / (n * n))
        return 1 - r  // Higher value means more dispersed (more suspicious)
    }
    
    /**
     * Calculate how predictable the access pattern is
     */
    private fun calculatePatternPredictability(timeDiffs: List<Double>): Double {
        if (timeDiffs.size < 3) return 0.5
        
        // Simplified approach: check if consecutive differences are similar
        var similarCount = 0
        for (i in 1 until timeDiffs.size) {
            val ratio = if (timeDiffs[i] > timeDiffs[i-1]) {
                timeDiffs[i-1] / timeDiffs[i]
            } else {
                timeDiffs[i] / timeDiffs[i-1]
            }
            
            if (ratio > 0.8) similarCount++
        }
        
        return similarCount.toDouble() / (timeDiffs.size - 1)
    }
    
    /**
     * Calculate anomaly score based on extracted features
     */
    private fun calculateAnomalyScore(features: DoubleArray): Double {
        // Feature weights (importance of each feature)
        val weights = doubleArrayOf(0.3, 0.2, 0.15, 0.25, 0.1)
        
        // Calculate weighted anomaly score
        var score = 0.0
        for (i in features.indices) {
            // Convert each feature to an anomaly contribution (higher is more anomalous)
            val featureAnomaly = when (i) {
                0 -> features[0] // frequency (higher is more suspicious)
                1 -> features[1] // time variance (higher is more suspicious)
                2 -> features[2] // time of day variance (higher is more suspicious)
                3 -> features[3] // burst ratio (higher is more suspicious)
                4 -> 1 - features[4] // pattern predictability (lower is more suspicious)
                else -> 0.5 // fallback
            }
            
            score += featureAnomaly * weights[i]
        }
        
        return score
    }
    
    /**
     * Normalize a feature value to 0-1 range
     */
    private fun normalizeFeature(value: Double, min: Double, max: Double): Double {
        return when {
            value <= min -> 0.0
            value >= max -> 1.0
            else -> (value - min) / (max - min)
        }
    }
    
    /**
     * Calculate confidence in the anomaly detection
     */
    private fun calculateConfidence(score: Double): Double {
        // Higher confidence when score is far from the threshold
        val distanceFromThreshold = Math.abs(score - ANOMALY_THRESHOLD)
        return Math.min(0.5 + distanceFromThreshold, 0.99)
    }
    
    /**
     * Get anomaly score for a specific trap
     */
    fun getAnomalyScore(trapId: String): Double {
        return anomalyScores[trapId] ?: 0.0
    }
    
    /**
     * Get all trap anomaly scores
     */
    fun getAllAnomalyScores(): Map<String, Double> {
        return anomalyScores.toMap()
    }
    
    /**
     * Train the model based on current patterns
     * (This is a simplified implementation for demonstration)
     */
    fun trainModel() {
        // In a real implementation, this would train the ML model
        // using collected feature vectors
        // For now, we're using rule-based scoring
    }
    
    /**
     * Get all feature vectors for analysis
     */
    fun getFeatureVectors(): Map<String, DoubleArray> {
        return featureVectors.toMap()
    }
    
    /**
     * Clear historical data for a trap
     */
    fun clearTrapHistory(trapId: String) {
        accessHistory.remove(trapId)
        anomalyScores.remove(trapId)
        featureVectors.remove(trapId)
    }
    
    /**
     * Data class representing a trap access event
     */
    data class AccessEvent(
        val trapId: String,
        val trapType: CloneDetectionService.TrapType,
        val timestamp: Long
    )
    
    /**
     * Data class representing the analysis result of a trap access
     */
    data class AccessAnalysis(
        val trapId: String,
        val anomalyScore: Double,
        val isSuspicious: Boolean,
        val confidence: Double,
        val features: List<Double>,
        val suggestedAction: SuggestedAction
    )
    
    /**
     * Enum for suggested actions based on analysis
     */
    enum class SuggestedAction {
        NORMAL_OPERATION,
        FLAG_FOR_REVIEW,
        INCREASE_MONITORING,
        BLOCK_AND_ALERT
    }
} 
package com.example.detection.honeypot.emotiontrap

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.UUID
import kotlin.math.abs

/**
 * Utility class for analyzing emotional patterns in user behavior
 * Used by the EmotionalDeceptionEnvironmentService to detect potential malware
 * that targets users during emotionally vulnerable states
 */
class EmotionalPatternAnalyzer(private val context: Context) {
    private val TAG = "EmotionalPatternAnalyzer"
    private val analyzerScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    
    // Baseline typing patterns for different emotional states
    private val baselineTypingPatterns = mapOf(
        EmotionalDeceptionEnvironmentService.EmotionalState.ANXIETY to TypingPattern(
            typingSpeed = 1.4f,      // Faster than normal
            errorRate = 0.12f,       // Higher error rate
            backspaceFrequency = 0.25f, // Frequent corrections
            pauseDuration = 0.5f     // Short pauses
        ),
        EmotionalDeceptionEnvironmentService.EmotionalState.FINANCIAL_STRESS to TypingPattern(
            typingSpeed = 1.35f,     // Faster than normal
            errorRate = 0.08f,       // Moderate error rate
            backspaceFrequency = 0.15f, // Some corrections
            pauseDuration = 0.6f     // Moderate pauses
        ),
        EmotionalDeceptionEnvironmentService.EmotionalState.URGENCY to TypingPattern(
            typingSpeed = 1.5f,      // Very fast
            errorRate = 0.15f,       // High error rate
            backspaceFrequency = 0.1f, // Few corrections (rushing)
            pauseDuration = 0.3f     // Very short pauses
        )
    )
    
    // Baseline cursor movement patterns for different emotional states
    private val baselineCursorPatterns = mapOf(
        EmotionalDeceptionEnvironmentService.EmotionalState.ANXIETY to CursorPattern(
            movementSpeed = 1.3f,     // Faster than normal
            directness = 0.6f,        // Less direct paths
            clickPressure = 1.1f,     // Slightly harder clicks
            doubleClickFrequency = 1.2f // More double clicks
        ),
        EmotionalDeceptionEnvironmentService.EmotionalState.FRUSTRATION to CursorPattern(
            movementSpeed = 1.4f,     // Fast, jerky movements
            directness = 0.5f,        // Erratic paths
            clickPressure = 1.3f,     // Hard clicks
            doubleClickFrequency = 1.5f // Many repeated clicks
        ),
        EmotionalDeceptionEnvironmentService.EmotionalState.ANGER to CursorPattern(
            movementSpeed = 1.5f,     // Very fast movements
            directness = 0.7f,        // Somewhat direct
            clickPressure = 1.5f,     // Very hard clicks
            doubleClickFrequency = 1.8f // Many repeated/double clicks
        )
    )
    
    /**
     * Generate simulated typing patterns based on emotional state
     * 
     * @param emotionalState The emotional state to simulate
     * @param baseText The base text to modify based on emotional patterns
     * @return The modified text with emotional patterns applied
     */
    fun generateEmotionalTypingPattern(
        emotionalState: EmotionalDeceptionEnvironmentService.EmotionalState, 
        baseText: String
    ): String {
        // Get the baseline pattern or use default values
        val baseline = baselineTypingPatterns[emotionalState] ?: TypingPattern()
        
        // Apply emotional patterns to the text
        return when (emotionalState) {
            EmotionalDeceptionEnvironmentService.EmotionalState.ANXIETY -> {
                addTypingErrors(baseText, baseline.errorRate)
                    .let { addBackspaceMarkers(it, baseline.backspaceFrequency) }
                    .let { addRepetitiveCharacters(it, 0.1f) } // Occasional repeated chars
            }
            EmotionalDeceptionEnvironmentService.EmotionalState.FINANCIAL_STRESS -> {
                addTypingErrors(baseText, baseline.errorRate * 0.8f) // Fewer errors in financial matters
                    .let { addUrgencyMarkers(it) }
            }
            EmotionalDeceptionEnvironmentService.EmotionalState.ANGER -> {
                baseText.uppercase() // CAPS LOCK ON
                    .let { addExclamationPoints(it, 0.3f) } // More exclamation points!!!!
                    .let { addTypingErrors(it, baseline.errorRate * 1.2f) } // More errors when angry
            }
            EmotionalDeceptionEnvironmentService.EmotionalState.URGENCY -> {
                addTypingErrors(baseText, baseline.errorRate)
                    .let { truncateWords(it, 0.15f) } // Truncate some words when in a hurry
                    .let { addUrgencyMarkers(it) }
            }
            else -> baseText // Default case
        }
    }
    
    /**
     * Generate cursor movement data based on emotional state
     * 
     * @param emotionalState The emotional state to simulate
     * @return A list of cursor movements that simulate the emotional state
     */
    fun generateCursorMovementData(
        emotionalState: EmotionalDeceptionEnvironmentService.EmotionalState
    ): List<CursorMovement> {
        // Get the baseline pattern or use default values
        val baseline = baselineCursorPatterns[emotionalState] ?: CursorPattern()
        
        // Create simulated cursor movements
        val movements = mutableListOf<CursorMovement>()
        val movementCount = (20 * baseline.movementSpeed).toInt()
        
        for (i in 0 until movementCount) {
            // Generate path with directness factor
            val path = if (Math.random() > baseline.directness) {
                "direct" // Direct path
            } else {
                "erratic" // Erratic path
            }
            
            // Generate pressure with emotional factor
            val pressure = baseline.clickPressure * (0.9f + (Math.random() * 0.2f).toFloat())
            
            // Generate movement speed
            val speed = baseline.movementSpeed * (0.8f + (Math.random() * 0.4f).toFloat())
            
            // Generate double-click based on frequency
            val isDoubleClick = Math.random() < (baseline.doubleClickFrequency - 1.0f) / 2.0f
            
            // Add to movements
            movements.add(
                CursorMovement(
                    id = UUID.randomUUID().toString(),
                    timestamp = System.currentTimeMillis() - (i * 100),
                    path = path,
                    pressure = pressure,
                    speed = speed,
                    isDoubleClick = isDoubleClick
                )
            )
        }
        
        return movements
    }
    
    /**
     * Analyze trap interactions for emotional patterns
     * 
     * @param interactions The trap interactions to analyze
     * @return Analysis results indicating suspicious patterns
     */
    fun analyzeInteractions(
        interactions: List<EmotionalDeceptionEnvironmentService.TrapInteraction>
    ): EmotionalAnalysisResult {
        // Skip analysis if no interactions
        if (interactions.isEmpty()) {
            return EmotionalAnalysisResult(
                detectedPatterns = emptyList(),
                anomalyScore = 0.0f,
                confidenceLevel = 0.0f
            )
        }
        
        // Detected emotional patterns
        val detectedPatterns = mutableListOf<String>()
        var anomalyScore = 0.0f
        
        // Check for rapid changes in interaction patterns
        if (detectRapidPatternChanges(interactions)) {
            detectedPatterns.add("Rapid behavioral changes detected")
            anomalyScore += 0.3f
        }
        
        // Check for unusual timing patterns
        if (detectUnusualTimingPatterns(interactions)) {
            detectedPatterns.add("Unusual interaction timing patterns")
            anomalyScore += 0.25f
        }
        
        // Check for inconsistent emotional indicators
        if (detectInconsistentEmotionalPatterns(interactions)) {
            detectedPatterns.add("Inconsistent emotional indicators")
            anomalyScore += 0.4f
        }
        
        // Check for robotic patterns in supposedly emotional interactions
        if (detectRoboticPatterns(interactions)) {
            detectedPatterns.add("Robotic patterns in emotional interactions")
            anomalyScore += 0.5f
        }
        
        // Calculate confidence based on number of interactions
        val confidenceLevel = (0.5f + (interactions.size.coerceAtMost(20) / 40.0f)).toFloat()
        
        // Cap anomaly score at 1.0
        anomalyScore = anomalyScore.coerceAtMost(1.0f)
        
        return EmotionalAnalysisResult(
            detectedPatterns = detectedPatterns,
            anomalyScore = anomalyScore,
            confidenceLevel = confidenceLevel
        )
    }
    
    /**
     * Detect rapid changes in interaction patterns
     */
    private fun detectRapidPatternChanges(
        interactions: List<EmotionalDeceptionEnvironmentService.TrapInteraction>
    ): Boolean {
        // Need at least 3 interactions to detect pattern changes
        if (interactions.size < 3) return false
        
        // Sort by timestamp
        val sorted = interactions.sortedBy { it.timestamp }
        var patternChangeCount = 0
        
        // Check for rapid changes in metadata patterns
        for (i in 0 until sorted.size - 1) {
            val current = sorted[i]
            val next = sorted[i + 1]
            
            // Check time difference (should be natural, not too precise or periodic)
            val timeDiff = next.timestamp - current.timestamp
            if (timeDiff < 50 || timeDiff % 1000 == 0L) {
                patternChangeCount++
            }
            
            // Check for abrupt pattern changes in metadata
            if (current.metadata.keys != next.metadata.keys) {
                patternChangeCount++
            }
        }
        
        return patternChangeCount >= interactions.size / 3
    }
    
    /**
     * Detect unusual timing patterns in interactions
     */
    private fun detectUnusualTimingPatterns(
        interactions: List<EmotionalDeceptionEnvironmentService.TrapInteraction>
    ): Boolean {
        // Need at least 3 interactions to detect timing patterns
        if (interactions.size < 3) return false
        
        // Sort by timestamp
        val sorted = interactions.sortedBy { it.timestamp }
        val intervals = mutableListOf<Long>()
        
        // Calculate intervals between interactions
        for (i in 0 until sorted.size - 1) {
            intervals.add(sorted[i + 1].timestamp - sorted[i].timestamp)
        }
        
        // Check for perfectly regular intervals (suspicious for bots)
        val regularCount = intervals.groupBy { it }.filter { it.value.size > 1 }.size
        if (regularCount > intervals.size / 3) {
            return true
        }
        
        // Check for too-fast intervals (inhuman)
        val tooFastCount = intervals.count { it < 200 } // Less than 200ms between actions
        if (tooFastCount > intervals.size / 4) {
            return true
        }
        
        return false
    }
    
    /**
     * Detect inconsistent emotional patterns
     */
    private fun detectInconsistentEmotionalPatterns(
        interactions: List<EmotionalDeceptionEnvironmentService.TrapInteraction>
    ): Boolean {
        // Extract emotion indicators from metadata
        val emotionIndicators = mutableMapOf<String, Int>()
        
        interactions.forEach { interaction ->
            interaction.metadata.forEach { (key, value) ->
                // Count indicators of specific emotional patterns
                when {
                    key.contains("typing_speed") && value == "faster than normal" -> 
                        emotionIndicators["fast_typing"] = (emotionIndicators["fast_typing"] ?: 0) + 1
                    
                    key.contains("caps_lock") && value == "frequent" ->
                        emotionIndicators["caps_usage"] = (emotionIndicators["caps_usage"] ?: 0) + 1
                    
                    key.contains("error_rate") && value == "high" ->
                        emotionIndicators["high_errors"] = (emotionIndicators["high_errors"] ?: 0) + 1
                    
                    key.contains("cursor_movement") && value == "erratic" ->
                        emotionIndicators["erratic_cursor"] = (emotionIndicators["erratic_cursor"] ?: 0) + 1
                }
            }
        }
        
        // Check for contradictory patterns (e.g., both very methodical and very erratic)
        val hasContradictoryPatterns = (emotionIndicators["fast_typing"] ?: 0) > interactions.size / 3 &&
                                      (emotionIndicators["erratic_cursor"] ?: 0) < interactions.size / 10
        
        return hasContradictoryPatterns
    }
    
    /**
     * Detect robotic patterns in supposedly emotional interactions
     */
    private fun detectRoboticPatterns(
        interactions: List<EmotionalDeceptionEnvironmentService.TrapInteraction>
    ): Boolean {
        // Check for perfectly consistent timing
        if (interactions.size >= 3) {
            val timestamps = interactions.map { it.timestamp }.sorted()
            val intervals = mutableListOf<Long>()
            
            for (i in 0 until timestamps.size - 1) {
                intervals.add(timestamps[i + 1] - timestamps[i])
            }
            
            // Calculate mean and standard deviation
            val mean = intervals.average()
            val stdDev = Math.sqrt(intervals.map { abs(it - mean) }.sum() / intervals.size)
            
            // Very low standard deviation suggests robotic timing
            if (stdDev < mean * 0.1) {
                return true
            }
        }
        
        // Check for identical metadata patterns
        val metadataFingerprints = interactions.map { 
            it.metadata.entries.sortedBy { entry -> entry.key }.joinToString { "${it.key}:${it.value}" }
        }
        
        // If more than half the interactions have identical metadata, likely robotic
        val mostCommonPattern = metadataFingerprints.groupBy { it }
            .maxByOrNull { it.value.size }?.value?.size ?: 0
            
        return mostCommonPattern > interactions.size / 2
    }
    
    /**
     * Add typing errors to a text string based on error rate
     */
    private fun addTypingErrors(text: String, errorRate: Float): String {
        if (text.isEmpty()) return text
        
        val result = StringBuilder(text)
        val errorCount = (text.length * errorRate).toInt().coerceAtLeast(1)
        
        repeat(errorCount) {
            val pos = (Math.random() * text.length).toInt()
            if (pos < result.length) {
                // 50% chance to replace with adjacent key, 50% chance to add a character
                if (Math.random() > 0.5 && pos > 0) {
                    // Replace with an adjacent key
                    result[pos] = getAdjacentKey(result[pos])
                } else {
                    // Add an extra character
                    result.insert(pos, getAdjacentKey(if (pos < text.length) text[pos] else 'e'))
                }
            }
        }
        
        return result.toString()
    }
    
    /**
     * Add backspace markers to text to simulate corrections
     */
    private fun addBackspaceMarkers(text: String, frequency: Float): String {
        if (text.isEmpty()) return text
        
        val result = StringBuilder()
        val words = text.split(" ")
        
        words.forEachIndexed { index, word ->
            // Decide whether to add a correction for this word
            if (Math.random() < frequency && word.length > 2) {
                // Simulate typing part of the word, backspacing, then completing correctly
                val errorPos = (word.length / 2).coerceAtLeast(1)
                val typo = getAdjacentKey(word[errorPos])
                
                // Add the first part of the word
                result.append(word.substring(0, errorPos))
                // Add the typo
                result.append(typo)
                // Add backspace marker
                result.append("⌫")
                // Complete the word correctly
                result.append(word.substring(errorPos))
            } else {
                result.append(word)
            }
            
            if (index < words.size - 1) {
                result.append(" ")
            }
        }
        
        return result.toString()
    }
    
    /**
     * Add repetitive characters to simulate nervous typing
     */
    private fun addRepetitiveCharacters(text: String, frequency: Float): String {
        if (text.isEmpty()) return text
        
        val result = StringBuilder(text)
        val repeatCount = (text.length * frequency).toInt().coerceAtLeast(1)
        
        repeat(repeatCount) {
            val pos = (Math.random() * text.length).toInt()
            if (pos < result.length && result[pos].isLetterOrDigit()) {
                // Repeat the character 1-3 times
                val char = result[pos]
                val repeats = (1 + Math.random() * 2).toInt()
                repeat(repeats) { result.insert(pos, char) }
            }
        }
        
        return result.toString()
    }
    
    /**
     * Add urgency markers to text
     */
    private fun addUrgencyMarkers(text: String): String {
        val urgencyPhrases = listOf(
            " urgent", " asap", " now", " quick", " immediately", 
            " emergency", " fast", " hurry"
        )
        
        // 30% chance to add an urgency phrase at the end
        return if (Math.random() < 0.3) {
            "$text${urgencyPhrases.random()}"
        } else {
            text
        }
    }
    
    /**
     * Add exclamation points to text
     */
    private fun addExclamationPoints(text: String, frequency: Float): String {
        if (text.isEmpty()) return text
        
        val result = StringBuilder(text)
        val sentences = text.split(Regex("[.!?]"))
        
        // Replace some periods with exclamation points and add extras
        var offset = 0
        sentences.forEachIndexed { _, sentence ->
            if (sentence.isNotEmpty()) {
                val endPos = offset + sentence.length
                if (endPos < result.length && Math.random() < frequency) {
                    // Replace period with exclamation point if present
                    if (result[endPos] == '.') {
                        result[endPos] = '!'
                    }
                    
                    // Add 1-3 extra exclamation points
                    val extras = (1 + Math.random() * 2).toInt()
                    repeat(extras) { result.insert(endPos + 1, '!') }
                }
                
                // Update offset for next sentence
                offset = endPos + 1
            }
        }
        
        return result.toString()
    }
    
    /**
     * Truncate some words to simulate hurried typing
     */
    private fun truncateWords(text: String, frequency: Float): String {
        if (text.isEmpty()) return text
        
        val words = text.split(" ")
        return words.joinToString(" ") { word ->
            if (word.length > 4 && Math.random() < frequency) {
                // Truncate the word, keeping at least 3 characters
                val keepChars = (3 + Math.random() * (word.length - 3)).toInt()
                word.substring(0, keepChars)
            } else {
                word
            }
        }
    }
    
    /**
     * Get an adjacent key on a QWERTY keyboard
     */
    private fun getAdjacentKey(char: Char): Char {
        val lowercase = char.lowercaseChar()
        
        // QWERTY keyboard layout adjacency map
        val adjacentKeys = mapOf(
            'a' to listOf('q', 'w', 's', 'z'),
            'b' to listOf('v', 'g', 'h', 'n'),
            'c' to listOf('x', 'd', 'f', 'v'),
            'd' to listOf('s', 'e', 'r', 'f', 'c', 'x'),
            'e' to listOf('w', 's', 'd', 'r'),
            'f' to listOf('d', 'r', 't', 'g', 'v', 'c'),
            'g' to listOf('f', 't', 'y', 'h', 'b', 'v'),
            'h' to listOf('g', 'y', 'u', 'j', 'n', 'b'),
            'i' to listOf('u', 'j', 'k', 'o'),
            'j' to listOf('h', 'u', 'i', 'k', 'm', 'n'),
            'k' to listOf('j', 'i', 'o', 'l', 'm'),
            'l' to listOf('k', 'o', 'p', ';'),
            'm' to listOf('n', 'j', 'k', ','),
            'n' to listOf('b', 'h', 'j', 'm'),
            'o' to listOf('i', 'k', 'l', 'p'),
            'p' to listOf('o', 'l', '[', ';'),
            'q' to listOf('1', '2', 'w', 'a'),
            'r' to listOf('e', 'd', 'f', 't'),
            's' to listOf('a', 'w', 'e', 'd', 'x', 'z'),
            't' to listOf('r', 'f', 'g', 'y'),
            'u' to listOf('y', 'h', 'j', 'i'),
            'v' to listOf('c', 'f', 'g', 'b'),
            'w' to listOf('q', 'a', 's', 'e'),
            'x' to listOf('z', 's', 'd', 'c'),
            'y' to listOf('t', 'g', 'h', 'u'),
            'z' to listOf('a', 's', 'x')
        )
        
        // Return an adjacent key if available, otherwise return the original
        val adjacent = adjacentKeys[lowercase]
        return if (adjacent != null && adjacent.isNotEmpty()) {
            val replacement = adjacent.random()
            if (char.isUpperCase()) replacement.uppercaseChar() else replacement
        } else {
            char
        }
    }
    
    /**
     * Data class for typing pattern characteristics
     */
    data class TypingPattern(
        val typingSpeed: Float = 1.0f,       // 1.0 = normal speed
        val errorRate: Float = 0.05f,        // 5% typos by default
        val backspaceFrequency: Float = 0.1f, // 10% backspace rate
        val pauseDuration: Float = 1.0f      // 1.0 = normal pauses
    )
    
    /**
     * Data class for cursor movement pattern characteristics
     */
    data class CursorPattern(
        val movementSpeed: Float = 1.0f,      // 1.0 = normal speed
        val directness: Float = 0.8f,         // 0.8 = mostly direct paths
        val clickPressure: Float = 1.0f,      // 1.0 = normal click pressure
        val doubleClickFrequency: Float = 1.0f // 1.0 = normal double-click frequency
    )
    
    /**
     * Data class for cursor movement data
     */
    data class CursorMovement(
        val id: String,
        val timestamp: Long,
        val path: String,
        val pressure: Float,
        val speed: Float,
        val isDoubleClick: Boolean
    )
    
    /**
     * Data class for emotional analysis results
     */
    data class EmotionalAnalysisResult(
        val detectedPatterns: List<String>,
        val anomalyScore: Float,
        val confidenceLevel: Float
    )
} 
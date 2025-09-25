package com.example.detection.ui.gamification

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min

/**
 * Security Gamification Manager
 * 
 * Provides gamification elements for the honeypot system to increase security awareness
 * through achievements, challenges, and rewards.
 */
class SecurityGamificationManager(private val context: Context) {

    companion object {
        private const val TAG = "SecurityGamification"
        private const val PREFS_FILENAME = "security_gamification_prefs"
        private const val KEY_ACHIEVEMENTS = "achievements"
        private const val KEY_CHALLENGES = "challenges"
        private const val KEY_SECURITY_SCORE = "security_score"
        private const val KEY_LAST_UPDATED = "last_updated"
        private const val KEY_STREAK_DAYS = "streak_days"
        private const val KEY_LAST_STREAK_CHECK = "last_streak_check"
        private const val KEY_USER_LEVEL = "user_level"
        private const val KEY_USER_XP = "user_xp"
        
        // XP needed for each level
        private val LEVEL_XP_REQUIREMENTS = listOf(
            0, 100, 250, 500, 1000, 1500, 2500, 4000, 6000, 10000, 15000
        )
    }
    
    // Master key for encrypted preferences
    private val masterKeyAlias by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }
    
    // Encrypted shared preferences for storing sensitive gamification data
    private val securePrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_FILENAME,
            masterKeyAlias,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    // Gson for serialization
    private val gson = Gson()
    
    // In-memory caches
    private val achievementsCache = ConcurrentHashMap<String, Achievement>()
    private val challengesCache = ConcurrentHashMap<String, Challenge>()
    private var securityScore = 0
    private var userLevel = 1
    private var userXP = 0
    private var streakDays = 0
    
    init {
        loadCachedData()
        checkDailyStreak()
    }
    
    /**
     * Load cached data from secure storage
     */
    private fun loadCachedData() {
        try {
            // Load achievements
            securePrefs.getString(KEY_ACHIEVEMENTS, null)?.let { json ->
                val type = object : TypeToken<Map<String, Achievement>>() {}.type
                val achievements: Map<String, Achievement> = gson.fromJson(json, type)
                achievementsCache.clear()
                achievementsCache.putAll(achievements)
            }
            
            // Load challenges
            securePrefs.getString(KEY_CHALLENGES, null)?.let { json ->
                val type = object : TypeToken<Map<String, Challenge>>() {}.type
                val challenges: Map<String, Challenge> = gson.fromJson(json, type)
                challengesCache.clear()
                challengesCache.putAll(challenges)
            }
            
            // Load other stats
            securityScore = securePrefs.getInt(KEY_SECURITY_SCORE, 0)
            streakDays = securePrefs.getInt(KEY_STREAK_DAYS, 0)
            userLevel = securePrefs.getInt(KEY_USER_LEVEL, 1)
            userXP = securePrefs.getInt(KEY_USER_XP, 0)
            
            // Initialize default achievements and challenges if none exist
            if (achievementsCache.isEmpty()) {
                initializeDefaultAchievements()
            }
            
            if (challengesCache.isEmpty()) {
                initializeDefaultChallenges()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error loading cached data: ${e.message}")
            // If there's an error, recreate default data
            initializeDefaultAchievements()
            initializeDefaultChallenges()
        }
    }
    
    /**
     * Save all data to secure storage
     */
    private fun saveData() {
        try {
            securePrefs.edit().apply {
                putString(KEY_ACHIEVEMENTS, gson.toJson(achievementsCache))
                putString(KEY_CHALLENGES, gson.toJson(challengesCache))
                putInt(KEY_SECURITY_SCORE, securityScore)
                putInt(KEY_STREAK_DAYS, streakDays)
                putLong(KEY_LAST_UPDATED, System.currentTimeMillis())
                putInt(KEY_USER_LEVEL, userLevel)
                putInt(KEY_USER_XP, userXP)
                apply()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error saving data: ${e.message}")
        }
    }
    
    /**
     * Initialize default achievements
     */
    private fun initializeDefaultAchievements() {
        val defaultAchievements = listOf(
            Achievement(
                id = "first_trap",
                title = "First Line of Defense",
                description = "Set up your first honeypot trap",
                icon = "🔒",
                xpReward = 50,
                securityPoints = 10,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 1,
                category = AchievementCategory.NOVICE
            ),
            Achievement(
                id = "trap_master",
                title = "Trap Master",
                description = "Create 10 different types of honeypot traps",
                icon = "🕸️",
                xpReward = 200,
                securityPoints = 50,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 10,
                category = AchievementCategory.INTERMEDIATE
            ),
            Achievement(
                id = "first_catch",
                title = "First Catch",
                description = "Detect your first security breach",
                icon = "🎣",
                xpReward = 100,
                securityPoints = 25,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 1,
                category = AchievementCategory.NOVICE
            ),
            Achievement(
                id = "vigilant_guardian",
                title = "Vigilant Guardian",
                description = "Check your honeypot dashboard for 7 consecutive days",
                icon = "👁️",
                xpReward = 150,
                securityPoints = 30,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 7,
                category = AchievementCategory.INTERMEDIATE
            ),
            Achievement(
                id = "security_expert",
                title = "Security Expert",
                description = "Reach a security score of 500",
                icon = "🛡️",
                xpReward = 300,
                securityPoints = 100,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 500,
                category = AchievementCategory.EXPERT
            ),
            Achievement(
                id = "honeypot_network",
                title = "Honeypot Network",
                description = "Set up at least one trap of each type",
                icon = "🌐",
                xpReward = 250,
                securityPoints = 75,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 3, // Assuming 3 types of traps
                category = AchievementCategory.ADVANCED
            ),
            Achievement(
                id = "threat_analyst",
                title = "Threat Analyst",
                description = "Review 50 threat intelligence reports",
                icon = "📊",
                xpReward = 400,
                securityPoints = 100,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 50,
                category = AchievementCategory.EXPERT
            ),
            Achievement(
                id = "master_of_deception",
                title = "Master of Deception",
                description = "Create 25 decoy elements",
                icon = "🎭",
                xpReward = 350,
                securityPoints = 90,
                isUnlocked = false,
                dateUnlocked = null,
                progressCurrent = 0,
                progressRequired = 25,
                category = AchievementCategory.ADVANCED
            )
        )
        
        achievementsCache.clear()
        defaultAchievements.forEach { achievement ->
            achievementsCache[achievement.id] = achievement
        }
    }
    
    /**
     * Initialize default challenges
     */
    private fun initializeDefaultChallenges() {
        val currentTime = System.currentTimeMillis()
        val oneDayInMillis = 24 * 60 * 60 * 1000L
        
        val defaultChallenges = listOf(
            Challenge(
                id = "daily_check",
                title = "Daily Security Check",
                description = "Check your honeypot dashboard today",
                icon = "📆",
                xpReward = 25,
                securityPoints = 5,
                startTime = currentTime,
                endTime = currentTime + oneDayInMillis,
                isCompleted = false,
                isRewarded = false,
                progressCurrent = 0,
                progressRequired = 1,
                challengeType = ChallengeType.DAILY
            ),
            Challenge(
                id = "three_traps",
                title = "Triple Threat",
                description = "Create 3 new honeypot traps this week",
                icon = "🎯",
                xpReward = 75,
                securityPoints = 15,
                startTime = currentTime,
                endTime = currentTime + (7 * oneDayInMillis),
                isCompleted = false,
                isRewarded = false,
                progressCurrent = 0,
                progressRequired = 3,
                challengeType = ChallengeType.WEEKLY
            ),
            Challenge(
                id = "review_logs",
                title = "Log Detective",
                description = "Review activity logs 3 times",
                icon = "🔍",
                xpReward = 50,
                securityPoints = 10,
                startTime = currentTime,
                endTime = currentTime + (3 * oneDayInMillis),
                isCompleted = false,
                isRewarded = false,
                progressCurrent = 0,
                progressRequired = 3,
                challengeType = ChallengeType.SHORT_TERM
            ),
            Challenge(
                id = "security_tuning",
                title = "Fine-Tuning",
                description = "Adjust your honeypot sensitivity profile",
                icon = "🎛️",
                xpReward = 40,
                securityPoints = 10,
                startTime = currentTime,
                endTime = currentTime + (2 * oneDayInMillis),
                isCompleted = false,
                isRewarded = false,
                progressCurrent = 0,
                progressRequired = 1,
                challengeType = ChallengeType.SHORT_TERM
            )
        )
        
        challengesCache.clear()
        defaultChallenges.forEach { challenge ->
            challengesCache[challenge.id] = challenge
        }
    }
    
    /**
     * Check for streak updates
     */
    private fun checkDailyStreak() {
        val calendar = Calendar.getInstance()
        val today = calendar.apply {
            set(Calendar.HOUR_OF_DAY, 0)
            set(Calendar.MINUTE, 0)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }.timeInMillis
        
        val lastCheck = securePrefs.getLong(KEY_LAST_STREAK_CHECK, 0)
        val lastCheckCal = Calendar.getInstance().apply { timeInMillis = lastCheck }
        val lastCheckDay = Calendar.getInstance().apply {
            timeInMillis = lastCheck
            set(Calendar.HOUR_OF_DAY, 0)
            set(Calendar.MINUTE, 0)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }.timeInMillis
        
        if (lastCheck == 0L) {
            // First time check
            streakDays = 1
        } else if (today - lastCheckDay > 24 * 60 * 60 * 1000) {
            // More than a day since last check
            val daysDifference = (today - lastCheckDay) / (24 * 60 * 60 * 1000)
            
            if (daysDifference == 1L) {
                // Consecutive day
                streakDays++
                
                // Give streak bonus
                if (streakDays % 5 == 0) {
                    // Bonus every 5 days
                    addSecurityScore(streakDays)
                    addXP(streakDays * 5)
                }
            } else {
                // Streak broken
                streakDays = 1
            }
        }
        
        securePrefs.edit().putLong(KEY_LAST_STREAK_CHECK, today).apply()
        securePrefs.edit().putInt(KEY_STREAK_DAYS, streakDays).apply()
    }
    
    /**
     * Record a trap creation event
     */
    fun recordTrapCreation(trapType: String) {
        // Update trap-related achievements
        val firstTrap = achievementsCache["first_trap"]
        if (firstTrap != null && !firstTrap.isUnlocked) {
            achievementsCache["first_trap"] = firstTrap.copy(
                progressCurrent = 1,
                progressRequired = 1,
                isUnlocked = true,
                dateUnlocked = System.currentTimeMillis()
            )
            
            // Award XP and security points
            addXP(firstTrap.xpReward)
            addSecurityScore(firstTrap.securityPoints)
        }
        
        // Update trap master achievement
        val trapMaster = achievementsCache["trap_master"]
        if (trapMaster != null && !trapMaster.isUnlocked) {
            // Count unique trap types
            val updatedProgress = min(trapMaster.progressCurrent + 1, trapMaster.progressRequired)
            val isComplete = updatedProgress >= trapMaster.progressRequired
            
            achievementsCache["trap_master"] = trapMaster.copy(
                progressCurrent = updatedProgress,
                isUnlocked = isComplete,
                dateUnlocked = if (isComplete) System.currentTimeMillis() else null
            )
            
            if (isComplete) {
                // Award XP and security points
                addXP(trapMaster.xpReward)
                addSecurityScore(trapMaster.securityPoints)
            }
        }
        
        // Update honeypot network achievement
        // This would need to be implemented with logic to track different trap types
        
        // Update challenges
        val tripleChallenge = challengesCache["three_traps"]
        if (tripleChallenge != null && !tripleChallenge.isCompleted) {
            val updatedProgress = min(tripleChallenge.progressCurrent + 1, tripleChallenge.progressRequired)
            val isComplete = updatedProgress >= tripleChallenge.progressRequired
            
            challengesCache["three_traps"] = tripleChallenge.copy(
                progressCurrent = updatedProgress,
                isCompleted = isComplete
            )
            
            if (isComplete && !tripleChallenge.isRewarded) {
                // Award XP and security points
                addXP(tripleChallenge.xpReward)
                addSecurityScore(tripleChallenge.securityPoints)
                
                challengesCache["three_traps"] = challengesCache["three_traps"]!!.copy(
                    isRewarded = true
                )
            }
        }
        
        // Save changes to storage
        saveData()
    }
    
    /**
     * Record a trap access event (breach detection)
     */
    fun recordTrapAccess() {
        // Update first catch achievement
        val firstCatch = achievementsCache["first_catch"]
        if (firstCatch != null && !firstCatch.isUnlocked) {
            achievementsCache["first_catch"] = firstCatch.copy(
                progressCurrent = 1,
                progressRequired = 1,
                isUnlocked = true,
                dateUnlocked = System.currentTimeMillis()
            )
            
            // Award XP and security points
            addXP(firstCatch.xpReward)
            addSecurityScore(firstCatch.securityPoints)
        }
        
        // Save changes to storage
        saveData()
    }
    
    /**
     * Record a dashboard check event
     */
    fun recordDashboardCheck() {
        // Update daily check challenge
        val dailyCheck = challengesCache["daily_check"]
        if (dailyCheck != null && !dailyCheck.isCompleted && System.currentTimeMillis() <= dailyCheck.endTime) {
            challengesCache["daily_check"] = dailyCheck.copy(
                progressCurrent = 1,
                progressRequired = 1,
                isCompleted = true
            )
            
            if (!dailyCheck.isRewarded) {
                // Award XP and security points
                addXP(dailyCheck.xpReward)
                addSecurityScore(dailyCheck.securityPoints)
                
                challengesCache["daily_check"] = challengesCache["daily_check"]!!.copy(
                    isRewarded = true
                )
            }
        }
        
        // Update vigilant guardian achievement
        val vigilantGuardian = achievementsCache["vigilant_guardian"]
        if (vigilantGuardian != null && !vigilantGuardian.isUnlocked) {
            // This would require more sophisticated tracking of consecutive days
            // Here we're just using the streak days we're already tracking
            if (streakDays >= vigilantGuardian.progressRequired) {
                achievementsCache["vigilant_guardian"] = vigilantGuardian.copy(
                    progressCurrent = vigilantGuardian.progressRequired,
                    isUnlocked = true,
                    dateUnlocked = System.currentTimeMillis()
                )
                
                // Award XP and security points
                addXP(vigilantGuardian.xpReward)
                addSecurityScore(vigilantGuardian.securityPoints)
            } else {
                achievementsCache["vigilant_guardian"] = vigilantGuardian.copy(
                    progressCurrent = streakDays
                )
            }
        }
        
        // Save changes to storage
        saveData()
    }
    
    /**
     * Record a log review event
     */
    fun recordLogReview() {
        // Update log review challenge
        val logChallenge = challengesCache["review_logs"]
        if (logChallenge != null && !logChallenge.isCompleted && System.currentTimeMillis() <= logChallenge.endTime) {
            val updatedProgress = min(logChallenge.progressCurrent + 1, logChallenge.progressRequired)
            val isComplete = updatedProgress >= logChallenge.progressRequired
            
            challengesCache["review_logs"] = logChallenge.copy(
                progressCurrent = updatedProgress,
                isCompleted = isComplete
            )
            
            if (isComplete && !logChallenge.isRewarded) {
                // Award XP and security points
                addXP(logChallenge.xpReward)
                addSecurityScore(logChallenge.securityPoints)
                
                challengesCache["review_logs"] = challengesCache["review_logs"]!!.copy(
                    isRewarded = true
                )
            }
        }
        
        // Save changes to storage
        saveData()
    }
    
    /**
     * Record a profile adjustment event
     */
    fun recordProfileAdjustment() {
        // Update profile tuning challenge
        val tuningChallenge = challengesCache["security_tuning"]
        if (tuningChallenge != null && !tuningChallenge.isCompleted && System.currentTimeMillis() <= tuningChallenge.endTime) {
            challengesCache["security_tuning"] = tuningChallenge.copy(
                progressCurrent = 1,
                progressRequired = 1,
                isCompleted = true
            )
            
            if (!tuningChallenge.isRewarded) {
                // Award XP and security points
                addXP(tuningChallenge.xpReward)
                addSecurityScore(tuningChallenge.securityPoints)
                
                challengesCache["security_tuning"] = challengesCache["security_tuning"]!!.copy(
                    isRewarded = true
                )
            }
        }
        
        // Save changes to storage
        saveData()
    }
    
    /**
     * Record decoy creation event
     */
    fun recordDecoyCreation() {
        // Update master of deception achievement
        val masterDeception = achievementsCache["master_of_deception"]
        if (masterDeception != null && !masterDeception.isUnlocked) {
            val updatedProgress = min(masterDeception.progressCurrent + 1, masterDeception.progressRequired)
            val isComplete = updatedProgress >= masterDeception.progressRequired
            
            achievementsCache["master_of_deception"] = masterDeception.copy(
                progressCurrent = updatedProgress,
                isUnlocked = isComplete,
                dateUnlocked = if (isComplete) System.currentTimeMillis() else null
            )
            
            if (isComplete) {
                // Award XP and security points
                addXP(masterDeception.xpReward)
                addSecurityScore(masterDeception.securityPoints)
            }
        }
        
        // Save changes to storage
        saveData()
    }
    
    /**
     * Record threat intelligence review
     */
    fun recordThreatIntelligenceReview() {
        // Update threat analyst achievement
        val threatAnalyst = achievementsCache["threat_analyst"]
        if (threatAnalyst != null && !threatAnalyst.isUnlocked) {
            val updatedProgress = min(threatAnalyst.progressCurrent + 1, threatAnalyst.progressRequired)
            val isComplete = updatedProgress >= threatAnalyst.progressRequired
            
            achievementsCache["threat_analyst"] = threatAnalyst.copy(
                progressCurrent = updatedProgress,
                isUnlocked = isComplete,
                dateUnlocked = if (isComplete) System.currentTimeMillis() else null
            )
            
            if (isComplete) {
                // Award XP and security points
                addXP(threatAnalyst.xpReward)
                addSecurityScore(threatAnalyst.securityPoints)
            }
        }
        
        // Save changes to storage
        saveData()
    }
    
    /**
     * Add XP to user and check for level up
     */
    private fun addXP(amount: Int) {
        userXP += amount
        
        // Check for level up
        while (userLevel < LEVEL_XP_REQUIREMENTS.size - 1 && 
               userXP >= LEVEL_XP_REQUIREMENTS[userLevel]) {
            userLevel++
            // Could trigger a level up notification/event here
        }
        
        securePrefs.edit()
            .putInt(KEY_USER_XP, userXP)
            .putInt(KEY_USER_LEVEL, userLevel)
            .apply()
    }
    
    /**
     * Add security score points
     */
    private fun addSecurityScore(amount: Int) {
        securityScore += amount
        
        // Check security expert achievement
        val securityExpert = achievementsCache["security_expert"]
        if (securityExpert != null && !securityExpert.isUnlocked) {
            val updatedProgress = min(securityScore, securityExpert.progressRequired)
            val isComplete = updatedProgress >= securityExpert.progressRequired
            
            achievementsCache["security_expert"] = securityExpert.copy(
                progressCurrent = updatedProgress,
                isUnlocked = isComplete,
                dateUnlocked = if (isComplete) System.currentTimeMillis() else null
            )
            
            if (isComplete) {
                // Award XP
                addXP(securityExpert.xpReward)
            }
        }
        
        securePrefs.edit().putInt(KEY_SECURITY_SCORE, securityScore).apply()
    }
    
    /**
     * Get all achievements
     */
    fun getAllAchievements(): List<Achievement> {
        return achievementsCache.values.toList()
    }
    
    /**
     * Get unlocked achievements
     */
    fun getUnlockedAchievements(): List<Achievement> {
        return achievementsCache.values.filter { it.isUnlocked }
    }
    
    /**
     * Get active challenges
     */
    fun getActiveChallenges(): List<Challenge> {
        val currentTime = System.currentTimeMillis()
        return challengesCache.values.filter { 
            !it.isCompleted && currentTime <= it.endTime 
        }
    }
    
    /**
     * Get completed challenges
     */
    fun getCompletedChallenges(): List<Challenge> {
        return challengesCache.values.filter { it.isCompleted }
    }
    
    /**
     * Get user's current level
     */
    fun getUserLevel(): Int {
        return userLevel
    }
    
    /**
     * Get user's current XP
     */
    fun getUserXP(): Int {
        return userXP
    }
    
    /**
     * Get XP required for next level
     */
    fun getXPForNextLevel(): Int {
        if (userLevel >= LEVEL_XP_REQUIREMENTS.size - 1) {
            return 0 // Max level reached
        }
        return LEVEL_XP_REQUIREMENTS[userLevel]
    }
    
    /**
     * Get current security score
     */
    fun getSecurityScore(): Int {
        return securityScore
    }
    
    /**
     * Get current streak days
     */
    fun getStreakDays(): Int {
        return streakDays
    }
    
    /**
     * Generate new daily challenges
     */
    fun refreshDailyChallenges() {
        val currentTime = System.currentTimeMillis()
        val oneDayInMillis = 24 * 60 * 60 * 1000L
        
        // Remove expired challenges
        val expiredChallenges = challengesCache.values.filter { 
            it.challengeType == ChallengeType.DAILY && currentTime > it.endTime 
        }
        
        expiredChallenges.forEach { challenge ->
            challengesCache.remove(challenge.id)
        }
        
        // Create new daily challenge
        val dailyCheckId = "daily_check_${Date().time}"
        challengesCache[dailyCheckId] = Challenge(
            id = dailyCheckId,
            title = "Daily Security Check",
            description = "Check your honeypot dashboard today",
            icon = "📆",
            xpReward = 25,
            securityPoints = 5,
            startTime = currentTime,
            endTime = currentTime + oneDayInMillis,
            isCompleted = false,
            isRewarded = false,
            progressCurrent = 0,
            progressRequired = 1,
            challengeType = ChallengeType.DAILY
        )
        
        saveData()
    }
}

/**
 * Achievement data class
 */
data class Achievement(
    val id: String,
    val title: String,
    val description: String,
    val icon: String,
    val xpReward: Int,
    val securityPoints: Int,
    val isUnlocked: Boolean,
    val dateUnlocked: Long?,
    val progressCurrent: Int,
    val progressRequired: Int,
    val category: AchievementCategory
)

/**
 * Challenge data class
 */
data class Challenge(
    val id: String,
    val title: String,
    val description: String,
    val icon: String,
    val xpReward: Int,
    val securityPoints: Int,
    val startTime: Long,
    val endTime: Long,
    val isCompleted: Boolean,
    val isRewarded: Boolean,
    val progressCurrent: Int,
    val progressRequired: Int,
    val challengeType: ChallengeType
)

/**
 * Achievement categories
 */
enum class AchievementCategory {
    NOVICE,
    INTERMEDIATE,
    ADVANCED,
    EXPERT,
    MASTER
}

/**
 * Challenge types
 */
enum class ChallengeType {
    DAILY,
    WEEKLY,
    SHORT_TERM,
    LONG_TERM
} 
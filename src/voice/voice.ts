/**
 * FORTBOT — Voice Module
 *
 * Speech-to-Text (STT) and Text-to-Speech (TTS) for WhatsApp audio.
 *
 * STT backends (in priority order):
 *   1. Local Whisper via whisper-cli (fastest, free, private)
 *   2. OpenAI Whisper API (needs API key)
 *   3. Claude tool-use with audio (if supported)
 *
 * TTS backends:
 *   1. espeak/piper (local, free, fast)
 *   2. System say/espeak command
 *
 * Audio format:
 *   WhatsApp sends .ogg (opus codec).
 *   Whisper needs .wav or .mp3.
 *   We convert with ffmpeg (must be installed).
 */

import { execSync, exec } from 'child_process';
import { existsSync, writeFileSync, readFileSync, unlinkSync, mkdirSync } from 'fs';
import { join } from 'path';
import { randomBytes } from 'crypto';

const TEMP_DIR = join(process.cwd(), '.voice_tmp');

// Ensure temp dir exists
try { mkdirSync(TEMP_DIR, { recursive: true }); } catch { /* already exists */ }

export interface TranscriptionResult {
  text: string;
  language?: string;
  duration?: number;
  backend: 'whisper_local' | 'whisper_api' | 'fallback';
}

export interface TTSResult {
  audio: Buffer;
  format: 'ogg' | 'mp3';
  backend: 'piper' | 'espeak' | 'say';
}

// ═══════════════════════════════════════════
// STT — Speech to Text
// ═══════════════════════════════════════════

/**
 * Transcribe audio buffer (from WhatsApp voice note).
 * Automatically picks the best available backend.
 */
export async function transcribe(audioBuffer: Buffer, mimeType: string = 'audio/ogg'): Promise<TranscriptionResult> {
  const id = randomBytes(4).toString('hex');
  const inputPath = join(TEMP_DIR, `input_${id}.ogg`);
  const wavPath = join(TEMP_DIR, `input_${id}.wav`);

  try {
    // Write audio to temp file
    writeFileSync(inputPath, audioBuffer);

    // Convert to WAV (Whisper needs it)
    if (!convertToWav(inputPath, wavPath)) {
      return { text: '[No se pudo procesar el audio — falta ffmpeg]', backend: 'fallback' };
    }

    // Try backends in order
    const localResult = await transcribeWhisperLocal(wavPath);
    if (localResult) return localResult;

    // Fallback: can't transcribe
    return {
      text: '[Audio recibido pero no hay motor de transcripción disponible. Instalá whisper: pip install openai-whisper]',
      backend: 'fallback',
    };
  } finally {
    // Cleanup temp files
    cleanup(inputPath);
    cleanup(wavPath);
  }
}

function convertToWav(input: string, output: string): boolean {
  try {
    execSync(`ffmpeg -i "${input}" -ar 16000 -ac 1 -f wav "${output}" -y 2>/dev/null`, {
      timeout: 15_000,
    });
    return existsSync(output);
  } catch {
    return false;
  }
}

async function transcribeWhisperLocal(wavPath: string): Promise<TranscriptionResult | null> {
  // Check if whisper CLI is available
  try {
    execSync('which whisper 2>/dev/null || which whisper-cli 2>/dev/null', { timeout: 3000 });
  } catch {
    return null;
  }

  try {
    // Use the smallest model for speed
    const outputDir = TEMP_DIR;
    const cmd = `whisper "${wavPath}" --model tiny --language es --output_dir "${outputDir}" --output_format txt 2>/dev/null`;
    execSync(cmd, { timeout: 30_000 });

    // Read the output .txt file
    const baseName = wavPath.replace(/\.[^.]+$/, '');
    const txtPath = `${baseName}.txt`;
    if (existsSync(txtPath)) {
      const text = readFileSync(txtPath, 'utf-8').trim();
      cleanup(txtPath);
      // Also clean up other whisper output files
      for (const ext of ['.json', '.srt', '.vtt', '.tsv']) {
        cleanup(`${baseName}${ext}`);
      }
      return { text, language: 'es', backend: 'whisper_local' };
    }
    return null;
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════
// TTS — Text to Speech
// ═══════════════════════════════════════════

/**
 * Convert text to audio for WhatsApp voice note.
 * Returns OGG buffer ready to send via Baileys.
 */
export async function synthesize(text: string, language: string = 'es'): Promise<TTSResult | null> {
  const id = randomBytes(4).toString('hex');
  const wavPath = join(TEMP_DIR, `tts_${id}.wav`);
  const oggPath = join(TEMP_DIR, `tts_${id}.ogg`);

  try {
    // Try piper (high quality, local)
    if (await tryPiper(text, wavPath, language)) {
      if (convertToOgg(wavPath, oggPath)) {
        const audio = readFileSync(oggPath);
        return { audio, format: 'ogg', backend: 'piper' };
      }
    }

    // Try espeak (widely available)
    if (await tryEspeak(text, wavPath, language)) {
      if (convertToOgg(wavPath, oggPath)) {
        const audio = readFileSync(oggPath);
        return { audio, format: 'ogg', backend: 'espeak' };
      }
    }

    // macOS: try `say`
    if (process.platform === 'darwin' && await trySay(text, wavPath)) {
      if (convertToOgg(wavPath, oggPath)) {
        const audio = readFileSync(oggPath);
        return { audio, format: 'ogg', backend: 'say' };
      }
    }

    return null;
  } finally {
    cleanup(wavPath);
    cleanup(oggPath);
  }
}

async function tryPiper(text: string, outputPath: string, lang: string): Promise<boolean> {
  try {
    execSync('which piper 2>/dev/null', { timeout: 3000 });
    // Piper needs a model. Check if one exists.
    const modelPath = join(process.cwd(), '.voice_models', `${lang}.onnx`);
    if (!existsSync(modelPath)) return false;

    execSync(`echo "${text.replace(/"/g, '\\"')}" | piper --model "${modelPath}" --output_file "${outputPath}" 2>/dev/null`, {
      timeout: 15_000,
    });
    return existsSync(outputPath);
  } catch {
    return false;
  }
}

async function tryEspeak(text: string, outputPath: string, lang: string): Promise<boolean> {
  try {
    execSync('which espeak-ng 2>/dev/null || which espeak 2>/dev/null', { timeout: 3000 });
    const cmd = `espeak-ng -v ${lang} -w "${outputPath}" "${text.replace(/"/g, '\\"')}" 2>/dev/null || espeak -v ${lang} -w "${outputPath}" "${text.replace(/"/g, '\\"')}" 2>/dev/null`;
    execSync(cmd, { timeout: 10_000 });
    return existsSync(outputPath);
  } catch {
    return false;
  }
}

async function trySay(text: string, outputPath: string): Promise<boolean> {
  try {
    const aiffPath = outputPath.replace('.wav', '.aiff');
    execSync(`say -o "${aiffPath}" "${text.replace(/"/g, '\\"')}" 2>/dev/null`, { timeout: 10_000 });
    execSync(`ffmpeg -i "${aiffPath}" "${outputPath}" -y 2>/dev/null`, { timeout: 10_000 });
    cleanup(aiffPath);
    return existsSync(outputPath);
  } catch {
    return false;
  }
}

function convertToOgg(input: string, output: string): boolean {
  try {
    execSync(`ffmpeg -i "${input}" -c:a libopus -b:a 48k -vn "${output}" -y 2>/dev/null`, {
      timeout: 15_000,
    });
    return existsSync(output);
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════
// Capabilities check
// ═══════════════════════════════════════════

export interface VoiceCapabilities {
  ffmpeg: boolean;
  whisper: boolean;
  espeak: boolean;
  piper: boolean;
  stt: boolean;
  tts: boolean;
}

export function checkVoiceCapabilities(): VoiceCapabilities {
  const has = (cmd: string) => {
    try {
      execSync(`which ${cmd} 2>/dev/null`, { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  };

  const ffmpeg = has('ffmpeg');
  const whisper = has('whisper') || has('whisper-cli');
  const espeak = has('espeak-ng') || has('espeak');
  const piper = has('piper');

  return {
    ffmpeg,
    whisper,
    espeak,
    piper,
    stt: ffmpeg && whisper,
    tts: ffmpeg && (espeak || piper),
  };
}

// ═══════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════

function cleanup(path: string): void {
  try { if (existsSync(path)) unlinkSync(path); } catch { /* ignore */ }
}

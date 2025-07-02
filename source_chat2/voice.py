import pyaudio
import wave
import os
import base64
import time
import threading
import sys
import uuid
import sounddevice as sd
import numpy as np
import warnings

# 在导入 pydub 之前过滤掉 RuntimeWarning
warnings.filterwarnings("ignore", category=RuntimeWarning, module='pydub.utils')


# 导入加密工具
import crypto_utils as c_utils

# 检查并尝试导入pydub和simpleaudio，并配置FFmpeg路径
try:
    from pydub import AudioSegment
    from pydub.playback import play

    current_module_dir = os.path.dirname(os.path.abspath(__file__))
    ffmpeg_bin_path = os.path.join(current_module_dir, 'ffmpeg_bin')

    ffmpeg_exe_path = os.path.join(ffmpeg_bin_path, 'ffmpeg.exe')
    ffprobe_exe_path = os.path.join(ffmpeg_bin_path, 'ffprobe.exe')

    if os.path.exists(ffmpeg_exe_path) and os.path.exists(ffprobe_exe_path):
        AudioSegment.converter = ffmpeg_exe_path
        # 对于较新版本的 pydub，可能还需要单独设置 AudioSegment.ffmpeg 和 AudioSegment.ffprobe
        AudioSegment.ffmpeg = ffmpeg_exe_path
        AudioSegment.ffprobe = ffprobe_exe_path
        PYDUB_AVAILABLE = True
    else:
        PYDUB_AVAILABLE = False
        print(f"[voice_module] 警告: 未找到 FFmpeg 可执行文件在 {ffmpeg_bin_path}。")
        print("                 请确保 ffmpeg_bin 文件夹内包含 ffmpeg.exe 和 ffprobe.exe。")
        print("                 语音消息功能将受限。")

except ImportError:
    PYDUB_AVAILABLE = False
    print(
        "警告: 未安装 pydub 或 simpleaudio，语音消息将使用 WAV 格式且播放可能受限。建议安装: pip install pydub simpleaudio")
    print("注意: pydub 还需要安装FFmpeg到ffmpeg_bin目录下。")



class VoiceRecorder:
    def __init__(self):
        self.stop_event = threading.Event()
        self.audio_format = pyaudio.paInt16
        self.channels = 1
        self.rate = 44100
        self.chunk = 1024
        self.p_audio_instance = None  # Store PyAudio instance

    def cleanup(self):
        """清理资源"""
        if self.p_audio_instance:
            self.p_audio_instance.terminate()
            self.p_audio_instance = None

    def get_audio_duration(self, file_path):
        """获取音频文件时长(秒)"""
        try:
            if PYDUB_AVAILABLE:
                audio = AudioSegment.from_wav(file_path)
                return len(audio) / 1000  # 转换为秒
            else:
                with wave.open(file_path, 'rb') as wf:
                    frames = wf.getnframes()
                    rate = wf.getframerate()
                    return frames / float(rate)
        except Exception as e:
            print(f"[语音模块] 获取音频时长失败: {e}")
            return 0

    def record_audio(self, filename_prefix, update_duration_callback):
        """
        录制音频并保存为 WAV 文件。
        :param filename_prefix: 保存的 WAV 文件名前缀（例如 "temp_voice"）。
        :param update_duration_callback: 用于更新录音时长的回调函数，接收当前秒数。
                                         此回调函数应由调用方负责在主线程中执行（例如通过 Tkinter 的 .after）。
        :return: 录制文件的完整路径，如果录制失败或文件为空则返回 None。
        """
        unique_filename = f"{filename_prefix}_{int(time.time())}.wav"

        if self.p_audio_instance is None:
            self.p_audio_instance = pyaudio.PyAudio()

        stream = None
        frames = []
        recorded_file_path = None

        try:
            stream = self.p_audio_instance.open(format=self.audio_format,
                                                channels=self.channels,
                                                rate=self.rate,
                                                input=True,
                                                frames_per_buffer=self.chunk)
            print("[语音模块] 开始录音...")
            start_time = time.time()
            self.stop_event.clear()  # Clear stop event for new recording

            while not self.stop_event.is_set():
                try:
                    data = stream.read(self.chunk, exception_on_overflow=False)
                    frames.append(data)
                    current_duration = int(time.time() - start_time)
                    update_duration_callback(current_duration)
                except IOError as e:
                    print(f"[语音模块] 录音流错误 (IOError): {e}")
                except Exception as e:
                    print(f"[语音模块] 录音过程中发生异常: {e}")
                    self.stop_event.set()

        except Exception as e:
            print(f"[语音模块] 打开录音流时发生异常: {e}")
            recorded_file_path = None
            self.stop_event.set()
        finally:
            if stream:
                if stream.is_active():
                    stream.stop_stream()
                stream.close()
            # PyAudio instance is terminated outside this block in client.py's cleanup

            print("[语音模块] 录音结束.")

            if not frames:
                print("[语音模块] 未录到任何音频帧。")
                return None

            try:
                sample_width = self.p_audio_instance.get_sample_size(
                    self.audio_format) if self.p_audio_instance else pyaudio.PyAudio().get_sample_size(
                    self.audio_format)

                wf = wave.open(unique_filename, 'wb')
                wf.setnchannels(self.channels)
                wf.setsampwidth(sample_width)
                wf.setframerate(self.rate)
                wf.writeframes(b''.join(frames))
                wf.close()
                recorded_file_path = unique_filename
                print(f"[语音模块] 录音保存到: {recorded_file_path}")
            except Exception as e:
                print(f"[语音模块] 保存录音文件失败: {e}")
                recorded_file_path = None

        # Terminate PyAudio instance after recording and saving
        if self.p_audio_instance:
            self.p_audio_instance.terminate()
            self.p_audio_instance = None

        return recorded_file_path

    def stop_recording(self):
        """停止录音"""
        print("[语音模块] 请求停止录音...")
        self.stop_event.set()

    def play_voice_message(self, encrypted_voice_b64=None, session_key=None, file_path=None):
        """
        解密并播放语音消息。
        如果提供了 file_path，则直接播放该文件，不再进行解密。
        """
        try:
            target_file_to_play = file_path
            if target_file_to_play is None:
                try:
                    voice_data = self.decrypt_voice_data(session_key, encrypted_voice_b64)
                    if not voice_data:
                        print("[语音模块] 语音解密失败。")
                        return

                    target_file_to_play = f"temp_received_voice_{int(time.time())}_{uuid.uuid4().hex}.wav"
                    with open(target_file_to_play, "wb") as f:
                        f.write(voice_data)
                    print(f"[语音模块] 已保存临时播放文件: {target_file_to_play}")
                except Exception as e:
                    print(f"[语音模块] 解密或保存接收到的语音文件失败: {e}")
                    return

            if target_file_to_play and os.path.exists(target_file_to_play):
                # 创建新线程播放，但不设为守护线程
                play_thread = threading.Thread(
                    target=self._play_thread,
                    args=(target_file_to_play,),
                    daemon=False  # 改为非守护线程
                )
                play_thread.start()
            else:
                print(f"[语音模块] 无法播放，文件不存在或无效: {target_file_to_play}")
        except Exception as e:
            print(f"[语音模块] 播放语音消息时发生错误: {e}")

    def decrypt_voice_data(self, session_key, encrypted_voice_b64):
        """解密语音数据"""
        try:
            encrypted_voice = base64.b64decode(encrypted_voice_b64)
            decrypted_voice = c_utils.aes_decrypt(session_key, encrypted_voice)
            return decrypted_voice
        except Exception as e:
            print(f"[语音模块] 解密语音数据失败: {e}")
            return None

    def encrypt_voice_data(self, session_key, voice_data):
        """加密语音数据"""
        try:
            encrypted_voice = c_utils.aes_encrypt(session_key, voice_data)
            return base64.b64encode(encrypted_voice).decode('utf-8')
        except Exception as e:
            print(f"[语音模块] 加密语音数据失败: {e}")
            return None

    def _play_thread(self, file_path):
        try:
            if not os.path.exists(file_path):
                print(f"[语音模块] 错误: 语音文件不存在: {file_path}")
                return

            # 创建独立的PyAudio实例用于播放
            p = pyaudio.PyAudio()
            stream = None
            wf = None

            try:
                if PYDUB_AVAILABLE:
                    audio = AudioSegment.from_wav(file_path)
                    try:
                        # 获取音频样本数组。pydub对于立体声会返回1D数组（交错），
                        # 而sounddevice期望2D数组（采样点数, 通道数）。
                        samples = audio.get_array_of_samples()
                        channels = audio.channels
                        frame_rate = audio.frame_rate

                        # 如果是多声道，需要重塑数组
                        if channels > 1:
                            # pydub返回的是bytes或array.array，转换为numpy数组
                            samples = np.array(samples).reshape(-1, channels)
                        else:
                            samples = np.array(samples)  # 单声道直接转numpy

                        # 使用 sounddevice 播放
                        sd.play(samples, samplerate=frame_rate)
                        sd.wait()  # 等待播放完成

                        print(f"[语音模块] 通过 sounddevice 播放完毕: {file_path}")

                    except Exception as sd_e:
                        print(f"[语音模块] 警告: 使用 sounddevice 播放失败 ({sd_e})，尝试使用 pydub.playback.play。")
                        # 如果 sounddevice 播放失败，回退到 pydub 默认的播放方式
                        play(audio)
                        print(f"[语音模块] 通过 pydub.playback.play 播放完毕: {file_path}")

                else:
                    # 保持原有的 pyaudio/wave 播放逻辑不变，作为 pydub 也不可用时的最终回退
                    p = pyaudio.PyAudio()  # 确保 p 对象在这里被初始化，或者它是一个类成员
                    wf = wave.open(file_path, 'rb')
                    stream = p.open(format=p.get_format_from_width(wf.getsampwidth()),
                                    channels=wf.getnchannels(),
                                    rate=wf.getframerate(),
                                    output=True)

                    data = wf.readframes(self.chunk)
                    while data:
                        stream.write(data)
                        data = wf.readframes(self.chunk)

                    stream.stop_stream()
                    # 只有当 p 对象在当前函数作用域内创建时才在这里终止
                    # 如果 p 是 VoiceRecorder 类的成员，则其生命周期应由类管理
                    stream.close()
                    wf.close()
                    # 如果 pyaudio.PyAudio() 在这里创建，则在这里终止
                    # 否则，如果您在 __init__ 中初始化它，请在 __del__ 或 on_closing 中终止
                    # 这里假设它是局部创建的
                    p.terminate()

                    print(f"[语音模块] 通过 PyAudio 播放完毕: {file_path}")
            except Exception as e:
                print(f"[语音模块] 播放过程中出错: {e}")
            finally:
                # 确保资源被正确释放
                if stream:
                    stream.close()
                if wf:
                    wf.close()
                p.terminate()

            print(f"[语音模块] 播放完毕: {file_path}")
        except Exception as e:
            print(f"[语音模块] 播放语音文件失败: {e}, 文件: {file_path}")
        finally:
            # 延迟删除文件，确保播放完成
            time.sleep(1)  # 等待1秒确保播放完成
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"[语音模块] 已删除临时播放文件: {file_path}")
            except Exception as e:
                print(f"[语音模块] 删除临时播放文件失败: {e}")
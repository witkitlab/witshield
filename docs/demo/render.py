#!/usr/bin/env python3
"""Render an explicitly edited replay from the sanitized real CLI capture."""

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


WIDTH, HEIGHT = 1440, 900
FONT_PATH = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"
COLORS = {
    "background": "#0a101b", "panel": "#101a29", "chrome": "#182536",
    "border": "#2a3b50", "white": "#e5edf6", "muted": "#93a8be",
    "cyan": "#7dd3fc", "green": "#86efac", "amber": "#fcd88a",
    "red": "#fca5a5", "note": "#142a38",
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def font(size, mono=False):
    # TTC face 7 is Noto Sans Mono CJK SC; face 2 is Noto Sans CJK SC.
    return ImageFont.truetype(FONT_PATH, size, index=7 if mono else 2)


def lines(text):
    return ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "").splitlines()


def excerpts(text, indices):
    original = lines(text)
    return [original[index] for index in indices]


def scenes(capture):
    chunks = capture["repair"]["chunks"]
    assert capture["before"]["score"] == 27 and capture["after"]["score"] == 63
    assert capture["before"]["coveragePercent"] == capture["after"]["coveragePercent"] == 87
    assert capture["repair"]["confirmationKeyProbe"]["success"]
    assert capture["repair"]["afterKeyProbe"]["success"]
    assert not capture["repair"]["afterPasswordProbe"]["success"]

    def pty(start, end):
        return lines("".join(chunk["data"] for chunk in chunks[start:end]))

    return [
        {
            "chapter": "01 / 03   先看清问题", "command": "sudo witshield check",
            "source": "真实报告节选 · 省略说明与手动命令，完整原文见 capture.json",
            "body": excerpts(capture["before"]["stdout"], list(range(1, 10)) + [10, 11, 12, 19, 24]),
            "note": "检查结果：27 分，6 个问题；SSH 密码登录和 shadow 权限可逐项修复。",
            "detail": "覆盖率 87%（7/8），没有读到 SSH 日志；未完成检查不代表没有风险。",
            "duration": 4500,
        },
        {
            "chapter": "02 / 03   先预览，再确认", "command": "sudo witshield check --fix --ssh-confirm-seconds 60",
            "source": "真实 PTY 输出 · SSH 预检与变更预览",
            "body": pty(3, 10),
            "note": "录制动作：已批准 SSH 修改；原始录制关闭输入回显，画面未补写 y。",
            "detail": "本次演示设置 60 秒确认窗口；产品默认 180 秒。",
            "duration": 4000,
        },
        {
            "chapter": "02 / 03   新连接可用，才确认保留", "command": "sudo witshield check --fix --ssh-confirm-seconds 60",
            "source": "真实 PTY 输出 · 保持原窗口，等待第二次登录确认",
            "body": pty(10, 11),
            "note": "录制验证：另一条全新 TCP SSH 密钥连接成功，已禁用连接复用。",
            "detail": "成功后才提交保留确认；这是录制器验证说明，并非 CLI 额外输出。",
            "duration": 5000,
        },
        {
            "chapter": "02 / 03   SSH 已确认，继续修复权限", "command": "sudo witshield check --fix --ssh-confirm-seconds 60",
            "source": "真实 PTY 输出 · SSH 完成与 shadow 预览",
            "body": pty(11, 15),
            "note": "录制动作：已批准 /etc/shadow 权限修复；未改动其余风险项。",
            "detail": "修复范围限定为 root:shadow 0640；CLI 逐项预检、预览并验证。",
            "duration": 3500,
        },
        {
            "chapter": "02 / 03   两项修复完成", "command": "sudo witshield check --fix --ssh-confirm-seconds 60",
            "source": "真实 PTY 输出 · shadow 修复与结果",
            "body": pty(15, 16),
            "note": "录制验证：修复后新建密钥连接仍成功，密码登录探测已被拒绝。",
            "detail": "确认场景实际耗时 0.277 秒；本动画按语义增加阅读停留。",
            "duration": 2500,
        },
        {
            "chapter": "03 / 03   再体检，确认结果", "command": "sudo witshield check",
            "source": "真实报告节选 · 省略说明与手动命令，完整原文见 capture.json",
            "body": excerpts(capture["after"]["stdout"], list(range(1, 10)) + [10, 11, 12, 19, 24, 30, 31]),
            "note": "27 → 63 分，仍有 4 个问题；root 登录策略和内核设置仍需人工处理。",
            "detail": "覆盖率仍为 87%，分数仅代表已完成的检查；这不是完整安全审计。",
            "duration": 6000,
        },
    ]


def wrap(text, chosen_font, width):
    if not text:
        return [""]
    result, current = [], ""
    for char in text:
        if current and chosen_font.getlength(current + char) > width:
            result.append(current)
            current = "    " + char
        else:
            current += char
    result.append(current)
    return result


def render(scene, number, progress):
    image = Image.new("RGB", (WIDTH, HEIGHT), COLORS["background"])
    draw = ImageDraw.Draw(image)
    draw.text((44, 25), "妙计巡御", font=font(32), fill=COLORS["white"])
    draw.text((234, 36), "一次性体检 · 确认后修复", font=font(21), fill=COLORS["muted"])
    draw.text((44, 80), "隔离测试环境演示 · Ubuntu 24.04 容器 / 真实 sshd / systemctl 测试适配器", font=font(20), fill=COLORS["muted"])
    draw.text((1020, 36), scene["chapter"], font=font(21), fill=COLORS["cyan"])

    draw.rounded_rectangle((40, 130, 1400, 748), radius=16, fill=COLORS["panel"], outline=COLORS["border"], width=2)
    draw.rounded_rectangle((41, 131, 1399, 177), radius=15, fill=COLORS["chrome"])
    draw.rectangle((41, 160, 1399, 177), fill=COLORS["chrome"])
    for x, color in [(66, "#fa9d91"), (88, "#f6d891"), (110, "#9ed8ac")]:
        draw.ellipse((x, 149, x + 11, 160), fill=color)
    draw.text((145, 139), "demo-vps  /  终端实录重播", font=font(19), fill=COLORS["muted"])
    draw.text((72, 192), "命令 · " + scene["command"], font=font(22, True), fill=COLORS["cyan"])
    draw.text((72, 229), scene["source"], font=font(16), fill=COLORS["muted"])
    draw.line((72, 262, 1368, 262), fill=COLORS["border"])

    output_font = font(21, True)
    y = 278
    for original in scene["body"]:
        color = COLORS["white"]
        if "安全分" in original:
            color = COLORS["green"] if number == 5 else COLORS["amber"]
        elif "没有读到" in original or "！" in original or "firewall:" in original:
            color = COLORS["amber"]
        elif "[高危]" in original:
            color = COLORS["red"]
        elif "完成：" in original or "修复结束" in original or "✓" in original:
            color = COLORS["green"]
        for line in wrap(original, output_font, 1294):
            assert y + 27 <= 736, f"Terminal text overflow in scene {number}: {original}"
            draw.text((72, y), line, font=output_font, fill=color)
            y += 27

    draw.rounded_rectangle((40, 766, 1400, 858), radius=12, fill=COLORS["note"])
    draw.text((62, 778), scene["note"], font=font(23), fill=COLORS["green"] if number in (2, 4, 5) else COLORS["white"])
    draw.text((62, 817), scene["detail"], font=font(19), fill=COLORS["muted"])
    for field in ("note", "detail"):
        assert font(23 if field == "note" else 19).getlength(scene[field]) < 1314
    draw.text((44, 872), "基于真实 stdout / PTY；画面为节选、换行与停留重排，非实时录屏。", font=font(15), fill=COLORS["muted"])
    draw.rounded_rectangle((850, 879, 1396, 883), radius=2, fill=COLORS["border"])
    draw.rounded_rectangle((850, 879, 850 + max(2, int(546 * progress)), 883), radius=2, fill=COLORS["cyan"])
    return image


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=here / "capture.json")
    parser.add_argument("--output", type=Path, default=here / "check.gif")
    parser.add_argument("--site-output", type=Path, default=here.parents[1] / "web/public/check-demo.gif")
    parser.add_argument("--preview-dir", type=Path)
    args = parser.parse_args()
    capture = json.loads(args.capture.read_text())
    storyboard = scenes(capture)
    total = sum(scene["duration"] for scene in storyboard)

    # Derive one palette from every scene and reuse it for every GIF frame.
    contact = Image.new("RGB", (720, 450 * len(storyboard)))
    for number, scene in enumerate(storyboard):
        frame = render(scene, number, 1)
        contact.paste(frame.resize((720, 450)), (0, 450 * number))
        if args.preview_dir:
            args.preview_dir.mkdir(parents=True, exist_ok=True)
            frame.save(args.preview_dir / f"scene-{number + 1}.png")
    palette = contact.quantize(colors=256, method=Image.Quantize.MEDIANCUT)
    frames, durations, elapsed = [], [], 0
    for number, scene in enumerate(storyboard):
        for offset in range(0, scene["duration"], 500):
            duration = min(500, scene["duration"] - offset)
            frames.append(render(scene, number, (elapsed + offset + duration) / total).quantize(palette=palette, dither=Image.Dither.NONE))
            durations.append(duration)
        elapsed += scene["duration"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(args.output, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True, disposal=1)
    args.site_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.output, args.site_output)

    with Image.open(args.output) as animation:
        duration = 0
        for index in range(animation.n_frames):
            animation.seek(index)
            duration += animation.info.get("duration", 0)
        assert animation.size == (WIDTH, HEIGHT)
        assert duration < 30000
        assert args.output.stat().st_size < 3 * 1024 * 1024
        assert args.output.read_bytes() == args.site_output.read_bytes()
        print(json.dumps({"dimensions": animation.size, "frames": animation.n_frames, "durationMs": duration,
                          "bytes": args.output.stat().st_size, "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                          "siteCopyEqual": True}, ensure_ascii=False))


if __name__ == "__main__":
    main()

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


def report_excerpt(text):
    original = lines(text)
    selected = [line for line in original if any(marker in line for marker in (
        "妙计巡御 ·", "安全分  ", "过去 24 小时：", "发现 ",
        "！有检查没能完成", "firewall:", 'exec: "nft"',
    ))]
    selected.extend(["", next(line for line in original if line == "最该先处理的 3 件事")])
    count = 0
    for line in original:
        if re.match(r"\s+[1-3]\. \[", line):
            selected.append(line)
            count += 1
        elif count and count <= 3 and line.startswith("     证据："):
            selected.append(line)
    return selected


def validate(capture):
    source, repair = capture["source"], capture["repair"]
    assert capture["schemaVersion"] == 2 and source["status"] == repair["status"] == "PASS"
    assert re.fullmatch(r"[a-f0-9]{40}", source["sourceCommit"])
    assert re.fullmatch(r"[a-f0-9]{40}", source["cliHardeningCommit"]) and source["buildVCSModified"] is False
    assert re.fullmatch(r"[a-f0-9]{64}", source["binarySHA256"])
    build_info = source["buildInfo"]
    assert build_info["binarySHA256"] == source["binarySHA256"]
    assert build_info["buildSettings"]["vcs.revision"] == source["sourceCommit"]
    assert build_info["buildSettings"]["vcs.modified"] == "false"
    assert build_info["humanVersion"] == source["binaryVersion"]
    assert source["guest"]["distribution"] == "Debian GNU/Linux 12"
    assert source["guest"]["pid1"] == "systemd" and "QEMU" in source["guest"]["virtualization"]
    assert source["terminalInputEcho"] is True
    baseline = repair["beforePasswordProbe"]
    assert baseline["commandSucceeded"] and baseline["authenticationMethods"] == ["password"]
    assert baseline["pubkeyDisabled"] and baseline["keyboardInteractiveDisabled"] and baseline["connectionReuseDisabled"]
    for name in ("beforeKeyProbe", "confirmationKeyProbe", "afterKeyProbe"):
        assert repair[name]["status"] == "PASS" and repair[name]["freshTcp"]
    assert not repair["afterPasswordProbe"]["commandSucceeded"]
    assert repair["afterPasswordProbe"]["exitCode"] == 255
    assert repair["afterPasswordProbe"]["pubkeyDisabled"] and repair["afterPasswordProbe"]["keyboardInteractiveDisabled"]
    assert repair["afterPasswordProbe"]["connectionReuseDisabled"]
    key_validation = repair["postCaptureKeyValidation"]
    assert key_validation["status"] == "PASS" and key_validation["authenticationMethods"] == ["publickey"]
    assert key_validation["options"]["ControlMaster"] == "no" and key_validation["options"]["ControlPath"] == "none"
    chunks = repair["chunks"]
    assert all(0 <= a["at"] <= b["at"] for a, b in zip(chunks, chunks[1:]))
    assert chunks[-1]["at"] <= source["repairElapsedSeconds"]
    assert "\n".join(lines("".join(chunk["data"] for chunk in chunks))) == "\n".join(lines(repair["stdout"]))
    assert [event["input"] for event in repair["inputEvents"]] == ["y", "yes", "y"]
    assert all(0 <= event["at"] <= source["repairElapsedSeconds"] for event in repair["inputEvents"])
    assert repair["stdout"].count("现在修改？ [y/N] y") == 2
    assert "新窗口能登录吗？输入 yes 确认，其他任意内容恢复原配置：yes" in repair["stdout"]
    for name in ("before", "after"):
        report = capture[name]
        assert hashlib.sha256(report["stdout"].encode()).hexdigest() == source["sourceSHA256"][f"{name}.stdout"]
        summary = re.search(r"安全分\s+(\d+)\s*/\s*100.*?完成检查\s+(\d+)/(\d+) 项", report["stdout"])
        assert tuple(map(int, summary.groups())) == (report["score"], report["completedChecks"], report["checks"])
        assert report["coveragePercent"] == report["completedChecks"] * 100 // report["checks"]
        assert int(re.search(r"发现 (\d+) 个问题", report["stdout"])[1]) == report["issueCount"]
    assert hashlib.sha256(repair["stdout"].encode()).hexdigest() == source["sourceSHA256"]["fix.stdout"]


def scenes(capture):
    validate(capture)
    before, after, source = capture["before"], capture["after"], capture["source"]
    pty = lines("".join(chunk["data"] for chunk in capture["repair"]["chunks"]))

    def find(marker, start=0):
        return next(index for index in range(start, len(pty)) if marker in pty[index])

    start = find("开始逐项修复")
    ssh_approval = find("现在修改？", start)
    ssh_verified = find("预检 ✓", ssh_approval)
    ssh_confirmation = find("新窗口能登录吗？", ssh_verified)
    ssh_done = find("完成：SSH", ssh_confirmation)
    shadow_approval = find("现在修改？", ssh_done)
    shadow_verified = find("预检 ✓", shadow_approval)
    check_command = "sudo /usr/local/bin/witshield check --no-color"
    repair_command = f"sudo /usr/local/bin/witshield check --fix --no-color --ssh-confirm-seconds {source['sshConfirmSeconds']}"

    def coverage(report):
        return f"{report['completedChecks']}/{report['checks']}（{report['coveragePercent']}%）"

    return [
        {
            "chapter": "01 / 03   先看清问题", "command": check_command,
            "source": "真实报告节选 · 省略说明与手动命令，完整原文见 capture.json",
            "body": report_excerpt(before["stdout"]),
            "note": f"基线验证：密码和密钥均能登录；报告发现 {before['issueCount']} 个问题，其中 2 项可确认修复。",
            "detail": f"完成检查 {coverage(before)}；缺少防火墙工具，分数只代表已完成的部分。",
            "duration": 4500,
        },
        {
            "chapter": "02 / 03   先预览，再确认", "command": repair_command,
            "source": "真实 PTY 输出 · SSH 预检与变更预览",
            "body": pty[start:ssh_approval + 1],
            "note": "录制动作：输入 y 批准 SSH；画面中的 y 来自真实 guest PTY 回显。",
            "detail": f"本次演示设置 {source['sshConfirmSeconds']} 秒确认窗口；产品默认 180 秒。",
            "duration": 4000,
        },
        {
            "chapter": "02 / 03   新连接可用，才确认保留", "command": repair_command,
            "source": "真实 PTY 输出 · 保持原窗口，等待第二次登录确认",
            "body": pty[ssh_verified:ssh_confirmation + 1],
            "note": "录制验证：另一条全新 TCP SSH 密钥连接成功后，才输入 yes 确认保留。",
            "detail": "ControlMaster=no / ControlPath=none；这是录制器说明，并非 CLI 额外输出。",
            "duration": 5000,
        },
        {
            "chapter": "02 / 03   SSH 已确认，继续修复权限", "command": repair_command,
            "source": "真实 PTY 输出 · SSH 完成与 shadow 预览",
            "body": pty[ssh_done:shadow_approval + 1],
            "note": "录制动作：输入 y 批准 /etc/shadow 权限修复；未改动其余风险项。",
            "detail": "范围说明：仅关闭 PasswordAuthentication；旧提示原文保留，不覆盖其他 SSH 认证机制。",
            "duration": 3500,
        },
        {
            "chapter": "02 / 03   两项修复完成", "command": repair_command,
            "source": "真实 PTY 输出 · shadow 修复与结果",
            "body": pty[shadow_verified:],
            "note": "录制验证：修复后新建密钥连接仍成功，密码登录探测已被拒绝。",
            "detail": f"交互录制实际耗时 {source['repairElapsedSeconds']} 秒；动画重排阅读停留，非实时录屏。",
            "duration": 2500,
        },
        {
            "chapter": "03 / 03   再体检，确认结果", "command": check_command,
            "source": "真实报告节选 · 省略说明与手动命令，完整原文见 capture.json",
            "body": report_excerpt(after["stdout"]),
            "note": f"{before['score']} → {after['score']} 分，仍有 {after['issueCount']} 个问题；root 密钥登录、内核指针和开放端口仍需评估。",
            "detail": f"完成检查仍为 {coverage(after)}；未完成防火墙检查，分数不是安全保证。",
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


def render(scene, number, progress, source):
    image = Image.new("RGB", (WIDTH, HEIGHT), COLORS["background"])
    draw = ImageDraw.Draw(image)
    draw.text((44, 25), "妙计巡御", font=font(32), fill=COLORS["white"])
    draw.text((234, 36), "一次性体检 · 确认后修复", font=font(21), fill=COLORS["muted"])
    environment = f"隔离测试演示 · Debian {source['guest']['version']} QEMU / 真实 systemd / sshd · 旧 {source['sourceCommit'][:7]} 构建"
    assert font(20).getlength(environment) < 1314
    draw.text((44, 80), environment, font=font(20), fill=COLORS["muted"])
    draw.text((1020, 36), scene["chapter"], font=font(21), fill=COLORS["cyan"])

    draw.rounded_rectangle((40, 130, 1400, 748), radius=16, fill=COLORS["panel"], outline=COLORS["border"], width=2)
    draw.rounded_rectangle((41, 131, 1399, 177), radius=15, fill=COLORS["chrome"])
    draw.rectangle((41, 160, 1399, 177), fill=COLORS["chrome"])
    for x, color in [(66, "#fa9d91"), (88, "#f6d891"), (110, "#9ed8ac")]:
        draw.ellipse((x, 149, x + 11, 160), fill=color)
    draw.text((145, 139), "demo-vps  /  终端实录重播", font=font(19), fill=COLORS["muted"])
    command_label = "调用说明 · " + scene["command"]
    assert font(22, True).getlength(command_label) < 1294
    draw.text((72, 192), command_label, font=font(22, True), fill=COLORS["cyan"])
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
    draw.text((44, 872), "真实 VM stdout / PTY 节选；Pillow 节奏重排，非实时录屏。", font=font(15), fill=COLORS["muted"])
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
        frame = render(scene, number, 1, capture["source"])
        contact.paste(frame.resize((720, 450)), (0, 450 * number))
        if args.preview_dir:
            args.preview_dir.mkdir(parents=True, exist_ok=True)
            frame.save(args.preview_dir / f"scene-{number + 1}.png")
    palette = contact.quantize(colors=256, method=Image.Quantize.MEDIANCUT)
    frames, durations, elapsed = [], [], 0
    for number, scene in enumerate(storyboard):
        for offset in range(0, scene["duration"], 500):
            duration = min(500, scene["duration"] - offset)
            frames.append(render(scene, number, (elapsed + offset + duration) / total, capture["source"]).quantize(palette=palette, dither=Image.Dither.NONE))
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
        assert 25000 <= duration < 30000
        assert args.output.stat().st_size < 3 * 1024 * 1024
        assert args.output.read_bytes() == args.site_output.read_bytes()
        print(json.dumps({"dimensions": animation.size, "frames": animation.n_frames, "durationMs": duration,
                          "bytes": args.output.stat().st_size, "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                          "siteCopyEqual": True}, ensure_ascii=False))


if __name__ == "__main__":
    main()

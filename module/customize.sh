#!/system/bin/sh
[ "$KSU" = true ] || [ "$KSU" = 1 ] || abort 'KernelSU required.'
[ "$BOOTMODE" = true ] || abort 'Install from Android.'
[ "$ARCH" = arm64 ] || abort 'ARM64 required.'
[ "$API" -ge 31 ] || abort 'Android 12 or newer required.'
OLD=/data/adb/modules/scoped_rkp
if [ "$MODPATH" != "$OLD" ]; then
  for item in config/scope.txt config/autostart; do
    if [ -f "$OLD/$item" ]; then cp "$OLD/$item" "$MODPATH/$item" || abort "Cannot preserve $item"; fi
  done
  if [ -f "$OLD/state/startup.failed" ] || [ -f "$OLD/state/autostart.failed" ] || [ -f "$OLD/state/autostart.pending" ]; then
    mkdir -p "$MODPATH/state"
    printf 'Previous activation incomplete; inspect before manual enable.\n' > "$MODPATH/state/startup.failed"
  fi
fi
set_perm_recursive "$MODPATH" 0 0 0755 0644
for item in bin/scoped-rkpctl bin/srkp_engine action.sh boot-completed.sh uninstall.sh; do
  set_perm "$MODPATH/$item" 0 0 0755
done
ui_print 'ScopedRKP: startup after Android boots and the first user unlocks.'
ui_print 'Package list preserved. Use a full ordinary reboot after this library update.'

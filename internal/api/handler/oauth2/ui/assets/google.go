package assets

import (
	"github.com/lithammer/dedent"
	"maragu.dev/gomponents"
)

func SVGGoogle(width, height int) gomponents.Node {
	return gomponents.Rawf(dedent.Dedent(`
		<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 24 24">
			<path
				fill="#EA4335"
				d="M5.27 9.76A7.08 7.08 0 0 1 16.42 6.5L19.9 3A11.97 11.97 0 0 0 1.24 6.65l4.03 3.11Z"
			/>
			<path
				fill="#34A853"
				d="M16.04 18.01A7.4 7.4 0 0 1 12 19.1a7.08 7.08 0 0 1-6.72-4.82l-4.04 3.06A11.96 11.96 0 0 0 12 24a11.4 11.4 0 0 0 7.83-3l-3.79-2.99Z"
			/>
			<path
				fill="#4A90E2"
				d="M19.83 21c2.2-2.05 3.62-5.1 3.62-9 0-.7-.1-1.47-.27-2.18H12v4.63h6.44a5.4 5.4 0 0 1-2.4 3.56l3.8 2.99Z"
			/>
			<path
				fill="#FBBC05"
				d="M5.28 14.27a7.12 7.12 0 0 1-.01-4.5L1.24 6.64A11.93 11.93 0 0 0 0 12c0 1.92.44 3.73 1.24 5.33l4.04-3.06Z"
			/>
			<style id="stylus-1" type="text/css" class="stylus">
				._wrapper_6hqet_97 {
					max-width: none !important;
				}
			</style>
		</svg>
	`), width, height)
}

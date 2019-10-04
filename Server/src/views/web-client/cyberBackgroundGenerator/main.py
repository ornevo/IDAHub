import random
import sys
import shutil
import math
import os
from PIL import Image, ImageDraw, ImageFont


#~ IMAGE DRAWING PARAMS ~#

NUM_MARGIN_BOTTOM = 28
NUM_MARGIN_RIGHT =  28

FONT_SIZE = 22

RAW_NUMBER_H = 16
RAW_NUMBER_W = 8

NUMBER_H = RAW_NUMBER_H + NUM_MARGIN_BOTTOM
NUMBER_W = RAW_NUMBER_W + NUM_MARGIN_RIGHT

STARTING_POSITION = (-1, -3)

NUM_OF_NUMBER_ROWS = 7
NUM_OF_NUMBER_COLS = 7

IMAGE_PX_DIM = (NUM_OF_NUMBER_COLS*NUMBER_W, NUM_OF_NUMBER_ROWS*NUMBER_H)


#~ ANIMATION PARAMS ~#
FPS = 12
ANIMATION_LENGTH = 9  # In seconds
TICKS_NUM = FPS * ANIMATION_LENGTH
TRANSITION_CHANCE = 1 / (FPS * 1)  # On average, every second
MAX_NUM_ALPHA = 80
MIN_NUM_ALPHA = 0
TRANSITION_TIME = 2  # In seconds


#~ SOME GLOBALS ~#
IMAGES_DIR = '/tmp/IDAHUB_CYBER_BACK_ANIMATION_IMAGES'
RESULT_FILE = ''
NUM_MATRIX = []

import inspect

class Number():
        def __init__(self):
                # Current values
                self.value = int(round(random.random()))
                self.current_alpha = Number.gen_alpha()

                self.initial_alpha = self.current_alpha
                self.is_finishing = False  # If true, comming back to the initial alpha to close the loop

                # transition data
                self.target_alpha = self.current_alpha
                # This is the step size we progress each tick (frame)
                self.alpha_velocity = 0
                self.marked = False

        def gen_alpha():
                gen = MIN_NUM_ALPHA + int(round(random.random() * (MAX_NUM_ALPHA - MIN_NUM_ALPHA)))
                return round(gen, 4)

        def to_mat_obj(self):
                return {'alpha': self.current_alpha, 'value': self.value}

        def get_alpha(self):
                return round(self.current_alpha)

        def get_value(self):
                return self.value

        def has_finished(self): 
                return self.is_finishing and self.has_reached_target()

        def has_reached_target(self):
                return abs(self.current_alpha - self.target_alpha) < max(abs(self.alpha_velocity), 0.0001)

        def update_velocity(self):
                self.alpha_velocity = round((self.target_alpha - self.current_alpha) / (TRANSITION_TIME * FPS), 4)

        def finish_off(self):
                '''
                close the loop
                '''
                self.is_finishing = True
                self.target_alpha = self.initial_alpha
                self.update_velocity()

        def tick(self):
                '''
                This function progress the number to the next frame state
                '''
                # First, if in transition, continue the transition
                if self.current_alpha != self.target_alpha:
                        if self.has_reached_target():
                               self.current_alpha = self.target_alpha
                        else:
                                self.current_alpha += self.alpha_velocity
                        # if self.marked:
                        #         print(self.current_alpha, self.target_alpha, self.alpha_velocity)
                        #         print(str(abs(self.current_alpha - self.target_alpha)) + " >= " + str(abs(max(self.alpha_velocity, 0.0001))))
                        if self.current_alpha < MIN_NUM_ALPHA or self.current_alpha > MAX_NUM_ALPHA:
                                print("WTF")
                        return

                # If here, in no transition
                if self.is_finishing or random.random() > TRANSITION_CHANCE:
                        return

                # If here, we should start a new transition
                self.target_alpha = Number.gen_alpha()
                self.update_velocity()


def initialize():
        '''
        Initializes globals
        '''
        global NUM_MATRIX, IMAGES_DIR, RESULT_FILE

        # Result file
        if len(sys.argv) != 2:
                print("Usage: " + sys.argv[0] + " <./output/webm/path.webm>")
                exit(1)

        RESULT_FILE = sys.argv[1]

        if RESULT_FILE.split(".")[-1] != "webm":
                RESULT_FILE += ".webm"

        # Tmp dir
        if not os.path.isdir("/tmp"):
                print("ERROR: Couldn't find /tmp: Please run in linux.")
                exit(1)
        if os.path.isdir(IMAGES_DIR):
                shutil.rmtree(IMAGES_DIR)
        os.mkdir(IMAGES_DIR)

        # Num matrix
        NUM_MATRIX = [ [ Number() for col in range(NUM_OF_NUMBER_COLS) ] for row in range(NUM_OF_NUMBER_ROWS) ]

        NUM_MATRIX[0][0].marked = True

        # For some reason, the first randomization generates very high alpha-s, though it gets smoother later. So we "dump" the first 5 seconds
        for row in NUM_MATRIX:
                for num in row:
                        for i in range(int(FPS * 12)):
                                num.tick()
                        num.initial_alpha = num.current_alpha                                


def tick():
        '''
        Simply ticks all the images
        '''
        for row in NUM_MATRIX:
                for num in row:
                        num.tick()


def image_generator(output_path, is_example_frame=False):
        '''
        Generates an image from the matrix, and writes the ourput image to output_path
        Each item in the value matrix should be in the following format:
        {'value': 0/1, 'alpha': 0-100}
        '''
        bg_color = (0, 0, 0, 100) if is_example_frame else (0, 0, 0, 0)

        img = Image.new('RGBA', IMAGE_PX_DIM, color = bg_color)
        font = ImageFont.truetype("firacode.ttf", FONT_SIZE)
        d = ImageDraw.Draw(img)
        for rowi in range(NUM_OF_NUMBER_ROWS):
                for coli in range(NUM_OF_NUMBER_COLS):
                        num_location = (STARTING_POSITION[0] + NUMBER_W*coli,
                                        STARTING_POSITION[1] + NUMBER_H*rowi)

                        num_obj = NUM_MATRIX[rowi][coli]

                        num_alpha = num_obj.get_alpha()
                        num_value = num_obj.get_value()

                        d.text(num_location, str(num_value), fill=(255,255,255,num_alpha), font=font)

        img.save(output_path)


def close_gif_loop():
        all_nums = []
        for row in NUM_MATRIX:
                all_nums.extend(row)

        for num in all_nums:
                num.finish_off()

        # It should take exatcly one transition time
        for i in range(TICKS_NUM, TICKS_NUM + int(TRANSITION_TIME * FPS)):
                curr_file = IMAGES_DIR + "/" + str(i).zfill(len(str(TICKS_NUM))) + ".png"
                image_generator(curr_file)
                tick()


def main():
        initialize()

        print("Generating frames...")
        
        i = 0
        for i in range(TICKS_NUM):
                print("{}/{}".format(i, TICKS_NUM))
                curr_file = IMAGES_DIR + "/" + str(i).zfill(len(str(TICKS_NUM))) + ".png"
                image_generator(curr_file)
                tick()

        print("Finishing off...")
        # Make it a perfect loop
        close_gif_loop()

        print("Saving.")
        if os.system("ffmpeg -framerate " + str(FPS) + " -f image2 -i " + IMAGES_DIR + "/\%03d.png -c:v libvpx-vp9 -pix_fmt yuva420p " + RESULT_FILE) != 0:
                print("Done. Result in " + RESULT_FILE)
        else:
                print("Error encoding to movie.")
                exit(1)


def gen_example_frame():
        initialize()
        image_generator("/tmp/AAA.png", is_example_frame=True)
        os.system("firefox /tmp/AAA.png")


if __name__ == "__main__":
        main()
        # gen_example_frame()
        